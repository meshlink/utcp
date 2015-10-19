/*
    utcp.c -- Userspace TCP
    Copyright (C) 2014 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "utcp_priv.h"

#ifndef EBADMSG
#define EBADMSG         104
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#ifdef poll
#undef poll
#endif

#ifndef timersub
#define timersub(a, b, r) do {\
	(r)->tv_sec = (a)->tv_sec - (b)->tv_sec;\
	(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;\
	if((r)->tv_usec < 0)\
		(r)->tv_sec--, (r)->tv_usec += 1000000;\
} while (0)
#endif

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef UTCP_DEBUG
#include <stdarg.h>

static void debug(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static void print_packet(struct utcp *utcp, const char *dir, const void *pkt, size_t len) {
	struct hdr hdr;
	if(len < sizeof hdr) {
		debug("%p %s: short packet (%zu bytes)\n", utcp, dir, len);
		return;
	}

	memcpy(&hdr, pkt, sizeof hdr);
	fprintf (stderr, "%p %s: len=%zu, src=%u dst=%u seq=%u ack=%u wnd=%u ctl=", utcp, dir, len, hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.wnd);
	if(hdr.ctl & SYN)
		debug("SYN");
	if(hdr.ctl & RST)
		debug("RST");
	if(hdr.ctl & FIN)
		debug("FIN");
	if(hdr.ctl & ACK)
		debug("ACK");

	if(len > sizeof hdr) {
		uint32_t datalen = len - sizeof hdr;
		uint8_t *str = malloc((datalen << 1) + 7);
		memcpy(str, " data=", 6);
		uint8_t *strptr = str + 6;
		const uint8_t *data = pkt;
		const uint8_t *dataend = data + datalen;

		while(data != dataend) {
			*strptr = (*data >> 4) > 9? (*data >> 4) + 55 : (*data >> 4) + 48;
			++strptr;
			*strptr = (*data & 0xf) > 9? (*data & 0xf) + 55 : (*data & 0xf) + 48;
			++strptr;
			++data;
		}
		*strptr = 0;

		debug(str);
		free(str);
	}

	debug("\n");
}
#else
#define debug(...)
#define print_packet(...)
#endif

static void set_state(struct utcp_connection *c, enum state state) {
	c->state = state;
	if(state == ESTABLISHED)
		timerclear(&c->conn_timeout);
	debug("%p new state: %s\n", c->utcp, strstate[state]);
}

static bool fin_wanted(struct utcp_connection *c, uint32_t seq) {
	if(seq != c->snd.last)
		return false;
	switch(c->state) {
	case FIN_WAIT_1:
	case CLOSING:
	case LAST_ACK:
		return true;
	default:
		return false;
	}
}

static inline void list_connections(struct utcp *utcp) {
	debug("%p has %d connections:\n", utcp, utcp->nconnections);
	for(int i = 0; i < utcp->nconnections; i++)
		debug("  %u -> %u state %s\n", utcp->connections[i]->src, utcp->connections[i]->dst, strstate[utcp->connections[i]->state]);
}

static int32_t seqdiff(uint32_t a, uint32_t b) {
	return a - b;
}

// Buffer functions
// TODO: convert to ringbuffers to avoid memmove() operations.

// Store data into the buffer
static ssize_t buffer_put_at(struct buffer *buf, size_t offset, const void *data, size_t len) {
	if(buf->maxsize <= buf->used)
		return 0;

	debug("buffer_put_at %zu %zu %zu\n", buf->used, offset, len);

	size_t required = offset + len;
	if(required > buf->maxsize) {
		if(offset >= buf->maxsize)
			return 0;
		abort();
		len = buf->maxsize - offset;
		required = buf->maxsize;
	}

	if(required > buf->size) {
		size_t newsize = buf->size;
		if(!newsize) {
			newsize = required;
		} else {
			do {
				newsize *= 2;
			} while(newsize < buf->used + len);
		}
		if(newsize > buf->maxsize)
			newsize = buf->maxsize;
		char *newdata = realloc(buf->data, newsize);
		if(!newdata)
			return -1;
		buf->data = newdata;
		buf->size = newsize;
	}

	memcpy(buf->data + offset, data, len);
	if(required > buf->used)
		buf->used = required;
	return len;
}

static ssize_t buffer_put(struct buffer *buf, const void *data, size_t len) {
	return buffer_put_at(buf, buf->used, data, len);
}

// Get data from the buffer. data can be NULL.
static ssize_t buffer_get(struct buffer *buf, void *data, size_t len) {
	if(len > buf->used)
		len = buf->used;
	if(data)
		memcpy(data, buf->data, len);
	if(len < buf->used)
		memmove(buf->data, buf->data + len, buf->used - len);
	buf->used -= len;
	return len;
}

// Copy data from the buffer without removing it.
static ssize_t buffer_copy(struct buffer *buf, void *data, size_t offset, size_t len) {
	if(offset >= buf->used)
		return 0;
	if(offset + len > buf->used)
		len = buf->used - offset;
	memcpy(data, buf->data + offset, len);
	return len;
}

static bool buffer_init(struct buffer *buf, uint32_t len, uint32_t maxlen) {
	memset(buf, 0, sizeof *buf);
	if(len) {
		buf->data = malloc(len);
		if(!buf->data)
			return false;
	}
	buf->size = len;
	buf->maxsize = maxlen;
	return true;
}

static void buffer_exit(struct buffer *buf) {
	free(buf->data);
	memset(buf, 0, sizeof *buf);
}

static uint32_t buffer_free(const struct buffer *buf) {
	return buf->maxsize - buf->used;
}

// Connections are stored in a sorted list.
// This gives O(log(N)) lookup time, O(N log(N)) insertion time and O(N) deletion time.

static int compare(const void *va, const void *vb) {
	assert(va && vb);

	const struct utcp_connection *a = *(struct utcp_connection **)va;
	const struct utcp_connection *b = *(struct utcp_connection **)vb;

	assert(a && b);
	assert(a->src && b->src);

	int c = (int)a->src - (int)b->src;
	if(c)
		return c;
	c = (int)a->dst - (int)b->dst;
	return c;
}

static struct utcp_connection *find_connection(const struct utcp *utcp, uint16_t src, uint16_t dst) {
	if(!utcp->nconnections)
		return NULL;
	struct utcp_connection key = {
		.src = src,
		.dst = dst,
	}, *keyp = &key;
	struct utcp_connection **match = bsearch(&keyp, utcp->connections, utcp->nconnections, sizeof *utcp->connections, compare);
	return match ? *match : NULL;
}

static void free_connection(struct utcp_connection *c) {
	struct utcp *utcp = c->utcp;
	struct utcp_connection **cp = bsearch(&c, utcp->connections, utcp->nconnections, sizeof *utcp->connections, compare);

	assert(cp);

	int i = cp - utcp->connections;
	memmove(cp, cp + 1, (utcp->nconnections - i - 1) * sizeof *cp);
	utcp->nconnections--;

	buffer_exit(&c->rcvbuf);
	buffer_exit(&c->sndbuf);
	free(c);
}

static struct utcp_connection *allocate_connection(struct utcp *utcp, uint16_t src, uint16_t dst) {
	// Check whether this combination of src and dst is free

	if(src) {
		if(find_connection(utcp, src, dst)) {
			errno = EADDRINUSE;
			return NULL;
		}
	} else { // If src == 0, generate a random port number with the high bit set
		if(utcp->nconnections >= 32767) {
			errno = ENOMEM;
			return NULL;
		}
		src = rand() | 0x8000;
		while(find_connection(utcp, src, dst))
			src++;
	}

	// Allocate memory for the new connection

	if(utcp->nconnections >= utcp->nallocated) {
		if(!utcp->nallocated)
			utcp->nallocated = 4;
		else
			utcp->nallocated *= 2;
		struct utcp_connection **new_array = realloc(utcp->connections, utcp->nallocated * sizeof *utcp->connections);
		if(!new_array)
			return NULL;
		utcp->connections = new_array;
	}

	struct utcp_connection *c = calloc(1, sizeof *c);
	if(!c)
		return NULL;

	if(!buffer_init(&c->sndbuf, DEFAULT_SNDBUFSIZE, DEFAULT_MAXSNDBUFSIZE)) {
		free(c);
		return NULL;
	}

	if(!buffer_init(&c->rcvbuf, DEFAULT_RCVBUFSIZE, DEFAULT_MAXRCVBUFSIZE)) {
		buffer_exit(&c->sndbuf);
		free(c);
		return NULL;
	}

	// Fill in the details

	c->src = src;
	c->dst = dst;
#ifdef UTCP_DEBUG
	c->snd.iss = 0;
#else
	c->snd.iss = rand();
#endif
	c->snd.una = c->snd.iss;
	c->snd.nxt = c->snd.iss + 1;
	c->rcv.wnd = utcp->mtu;
	c->snd.last = c->snd.nxt;
	c->snd.cwnd = utcp->mtu;
	c->utcp = utcp;

	// Add it to the sorted list of connections

	utcp->connections[utcp->nconnections++] = c;
	qsort(utcp->connections, utcp->nconnections, sizeof *utcp->connections, compare);

	return c;
}

// Update RTT variables. See RFC 6298.
static void update_rtt(struct utcp_connection *c, uint32_t rtt) {
	if(!rtt) {
		debug("invalid rtt\n");
		return;
	}

	struct utcp *utcp = c->utcp;

	if(!utcp->srtt) {
		utcp->srtt = rtt;
		utcp->rttvar = rtt / 2;
		utcp->rto = rtt + max(2 * rtt, CLOCK_GRANULARITY);
	} else {
		utcp->rttvar = (utcp->rttvar * 3 + abs(utcp->srtt - rtt)) / 4;
		utcp->srtt = (utcp->srtt * 7 + rtt) / 8;
		utcp->rto = utcp->srtt + max(utcp->rttvar, CLOCK_GRANULARITY);
	}

	if(utcp->rto > MAX_RTO)
		utcp->rto = MAX_RTO;

	debug("rtt %u srtt %u rttvar %u rto %u\n", rtt, utcp->srtt, utcp->rttvar, utcp->rto);
}

static void start_retransmit_timer(struct utcp_connection *c) {
	gettimeofday(&c->rtrx_timeout, NULL);
	c->rtrx_timeout.tv_usec += c->utcp->rto;
	while(c->rtrx_timeout.tv_usec >= 1000000) {
		c->rtrx_timeout.tv_usec -= 1000000;
		c->rtrx_timeout.tv_sec++;
	}
	debug("timeout set to %lu.%06lu (%u)\n", c->rtrx_timeout.tv_sec, c->rtrx_timeout.tv_usec, c->utcp->rto);
}

static void stop_retransmit_timer(struct utcp_connection *c) {
	timerclear(&c->rtrx_timeout);
	debug("timeout cleared\n");
}

struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv) {
	struct utcp_connection *c = allocate_connection(utcp, 0, dst);
	if(!c)
		return NULL;

	c->recv = recv;
	c->priv = priv;

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.iss;
	hdr.ack = 0;
	hdr.wnd = c->rcv.wnd;
	hdr.ctl = SYN;
	hdr.aux = 0;

	set_state(c, SYN_SENT);

	print_packet(utcp, "send", &hdr, sizeof hdr);
	utcp->send(utcp, &hdr, sizeof hdr);

	gettimeofday(&c->conn_timeout, NULL);
	c->conn_timeout.tv_sec += utcp->timeout;

	return c;
}

void utcp_accept(struct utcp_connection *c, utcp_recv_t recv, void *priv) {
	if(c->reapable || c->state != SYN_RECEIVED) {
		debug("Error: accept() called on invalid connection %p in state %s\n", c, strstate[c->state]);
		return;
	}

	debug("%p accepted, %p %p\n", c, recv, priv);
	c->recv = recv;
	c->priv = priv;
	set_state(c, ESTABLISHED);
}

static void ack(struct utcp_connection *c, bool sendatleastone) {
	int32_t left = seqdiff(c->snd.last, c->snd.nxt);
	int32_t cwndleft = c->snd.cwnd - seqdiff(c->snd.nxt, c->snd.una);
	debug("cwndleft = %d\n", cwndleft);

	assert(left >= 0);

	if(cwndleft <= 0)
		cwndleft = 0;

	if(cwndleft < left)
		left = cwndleft;

	if(!left && !sendatleastone)
		return;

	struct {
		struct hdr hdr;
		char data[];
	} *pkt;

	pkt = malloc(sizeof pkt->hdr + c->utcp->mtu);
	if(!pkt)
		return;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.ack = c->rcv.nxt;
	pkt->hdr.wnd = c->snd.wnd;
	pkt->hdr.ctl = ACK;
	pkt->hdr.aux = 0;

	do {
		uint32_t seglen = left > c->utcp->mtu ? c->utcp->mtu : left;
		pkt->hdr.seq = c->snd.nxt;

		buffer_copy(&c->sndbuf, pkt->data, seqdiff(c->snd.nxt, c->snd.una), seglen);

		c->snd.nxt += seglen;
		left -= seglen;

		if(seglen && fin_wanted(c, c->snd.nxt)) {
			seglen--;
			pkt->hdr.ctl |= FIN;
		}

		if(!c->rtt_start.tv_sec) {
			// Start RTT measurement
			gettimeofday(&c->rtt_start, NULL);
			c->rtt_seq = pkt->hdr.seq + seglen;
			debug("Starting RTT measurement, expecting ack %u\n", c->rtt_seq);
		}

		print_packet(c->utcp, "send", pkt, sizeof pkt->hdr + seglen);
		c->utcp->send(c->utcp, pkt, sizeof pkt->hdr + seglen);
	} while(left);

	free(pkt);
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
	if(c->reapable) {
		debug("Error: send() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	switch(c->state) {
	case CLOSED:
	case LISTEN:
	case SYN_SENT:
	case SYN_RECEIVED:
		debug("Error: send() called on unconnected connection %p\n", c);
		errno = ENOTCONN;
		return -1;
	case ESTABLISHED:
	case CLOSE_WAIT:
		break;
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		debug("Error: send() called on closing connection %p\n", c);
		errno = EPIPE;
		return -1;
	}

	// Add data to send buffer

	if(!len)
		return 0;

	if(!data) {
		errno = EFAULT;
		return -1;
	}

	len = buffer_put(&c->sndbuf, data, len);
	if(len <= 0) {
		errno = EWOULDBLOCK;
		return 0;
	}

	c->snd.last += len;
	ack(c, false);
	if(!timerisset(&c->rtrx_timeout))
		start_retransmit_timer(c);
	return len;
}

static void swap_ports(struct hdr *hdr) {
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

static void retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.last == c->snd.una) {
		debug("Retransmit() called but nothing to retransmit!\n");
		stop_retransmit_timer(c);
		return;
	}

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		char data[];
	} *pkt;

	pkt = malloc(sizeof pkt->hdr + c->utcp->mtu);
	if(!pkt)
		return;

	pkt->hdr.src = c->src;
	pkt->hdr.dst = c->dst;
	pkt->hdr.wnd = c->rcv.wnd;
	pkt->hdr.aux = 0;

	switch(c->state) {
		case SYN_SENT:
			// Send our SYN again
			pkt->hdr.seq = c->snd.iss;
			pkt->hdr.ack = 0;
			pkt->hdr.ctl = SYN;
			print_packet(c->utcp, "rtrx", pkt, sizeof pkt->hdr);
			utcp->send(utcp, pkt, sizeof pkt->hdr);
			break;

		case SYN_RECEIVED:
			// Send SYNACK again
			pkt->hdr.seq = c->snd.nxt;
			pkt->hdr.ack = c->rcv.nxt;
			pkt->hdr.ctl = SYN | ACK;
			print_packet(c->utcp, "rtrx", pkt, sizeof pkt->hdr);
			utcp->send(utcp, pkt, sizeof pkt->hdr);
			break;

		case ESTABLISHED:
		case FIN_WAIT_1:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
			// Send unacked data again.
			pkt->hdr.seq = c->snd.una;
			pkt->hdr.ack = c->rcv.nxt;
			pkt->hdr.ctl = ACK;
			uint32_t len = seqdiff(c->snd.last, c->snd.una);
			if(len > utcp->mtu)
				len = utcp->mtu;
			if(fin_wanted(c, c->snd.una + len)) {
				len--;
				pkt->hdr.ctl |= FIN;
			}
			c->snd.nxt = c->snd.una + len;
			c->snd.cwnd = utcp->mtu; // reduce cwnd on retransmit
			buffer_copy(&c->sndbuf, pkt->data, 0, len);
			print_packet(c->utcp, "rtrx", pkt, sizeof pkt->hdr + len);
			utcp->send(utcp, pkt, sizeof pkt->hdr + len);
			break;

		case CLOSED:
		case LISTEN:
		case TIME_WAIT:
		case FIN_WAIT_2:
			// We shouldn't need to retransmit anything in this state.
#ifdef UTCP_DEBUG
			abort();
#endif
			stop_retransmit_timer(c);
			goto cleanup;
	}

	start_retransmit_timer(c);
	utcp->rto *= 2;
	if(utcp->rto > MAX_RTO)
		utcp->rto = MAX_RTO;
	c->rtt_start.tv_sec = 0; // invalidate RTT timer

cleanup:
	free(pkt);
}

/* Update receive buffer and SACK entries after consuming data.
 *
 * Situation:
 *
 * |.....0000..1111111111.....22222......3333|
 * |---------------^
 *
 * 0..3 represent the SACK entries. The ^ indicates up to which point we want
 * to remove data from the receive buffer. The idea is to substract "len"
 * from the offset of all the SACK entries, and then remove/cut down entries
 * that are shifted to before the start of the receive buffer.
 *
 * There are three cases:
 * - the SACK entry is ahead of ^, in that case just change the offset.
 * - the SACK entry starts before and ends after ^, so we have to
 *   change both its offset and size.
 * - the SACK entry is completely before ^, in that case delete it.
 */
static void sack_consume(struct utcp_connection *c, size_t len) {
	debug("sack_consume %zu\n", len);
	if(len > c->rcvbuf.used)
		abort();

	buffer_get(&c->rcvbuf, NULL, len);

	for(int i = 0; i < NSACKS && c->sacks[i].len; ) {
		if(len < c->sacks[i].offset) {
			c->sacks[i].offset -= len;
			i++;
		} else if(len < c->sacks[i].offset + c->sacks[i].len) {
			c->sacks[i].len -= len - c->sacks[i].offset;
			c->sacks[i].offset = 0;
			i++;
		} else {
			if(i < NSACKS - 1) {
				memmove(&c->sacks[i], &c->sacks[i + 1], (NSACKS - 1 - i) * sizeof c->sacks[i]);
				c->sacks[NSACKS - 1].len = 0;
			} else {
				c->sacks[i].len = 0;
				break;
			}
		}
	}

	for(int i = 0; i < NSACKS && c->sacks[i].len; i++)
		debug("SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
}

static void handle_out_of_order(struct utcp_connection *c, uint32_t offset, const void *data, size_t len) {
	debug("out of order packet, offset %u\n", offset);
	// Packet loss or reordering occured. Store the data in the buffer.
	ssize_t rxd = buffer_put_at(&c->rcvbuf, offset, data, len);
	if(rxd < len)
		abort();

	// Make note of where we put it.
	for(int i = 0; i < NSACKS; i++) {
		if(!c->sacks[i].len) { // nothing to merge, add new entry
			debug("New SACK entry %d\n", i);
			c->sacks[i].offset = offset;
			c->sacks[i].len = rxd;
			break;
		} else if(offset < c->sacks[i].offset) {
			if(offset + rxd < c->sacks[i].offset) { // insert before
				if(!c->sacks[NSACKS - 1].len) { // only if room left
					debug("Insert SACK entry at %d\n", i);
					memmove(&c->sacks[i + 1], &c->sacks[i], (NSACKS - i - 1) * sizeof c->sacks[i]);
					c->sacks[i].offset = offset;
					c->sacks[i].len = rxd;
				}
				break;
			} else { // merge
				debug("Merge with start of SACK entry at %d\n", i);
				c->sacks[i].offset = offset;
				break;
			}
		} else if(offset <= c->sacks[i].offset + c->sacks[i].len) {
			if(offset + rxd > c->sacks[i].offset + c->sacks[i].len) { // merge
				debug("Merge with end of SACK entry at %d\n", i);
				c->sacks[i].len = offset + rxd - c->sacks[i].offset;
				// TODO: handle potential merge with next entry
			}
			break;
		}
	}

	for(int i = 0; i < NSACKS && c->sacks[i].len; i++)
		debug("SACK[%d] offset %u len %u\n", i, c->sacks[i].offset, c->sacks[i].len);
}

static void handle_in_order(struct utcp_connection *c, const void *data, size_t len) {
	// Check if we can process out-of-order data now.
	if(c->sacks[0].len && len >= c->sacks[0].offset) { // TODO: handle overlap with second SACK
		debug("incoming packet len %zu connected with SACK at %u\n", len, c->sacks[0].offset);
		buffer_put_at(&c->rcvbuf, 0, data, len); // TODO: handle return value
		len = max(len, c->sacks[0].offset + c->sacks[0].len);
		data = c->rcvbuf.data;
	}

	if(c->recv) {
		ssize_t rxd = c->recv(c, data, len);
		if(rxd != len) {
			// TODO: handle the application not accepting all data.
			abort();
		}
	}

	if(c->rcvbuf.used)
		sack_consume(c, len);

	c->rcv.nxt += len;
}


static void handle_incoming_data(struct utcp_connection *c, uint32_t seq, const void *data, size_t len) {
	uint32_t offset = seqdiff(seq, c->rcv.nxt);
	if(offset + len > c->rcvbuf.maxsize)
		abort();

	if(offset)
		handle_out_of_order(c, offset, data, len);
	else
		handle_in_order(c, data, len);
}


ssize_t utcp_recv(struct utcp *utcp, const void *data, size_t len) {
	if(!utcp) {
		errno = EFAULT;
		return -1;
	}

	if(!len)
		return 0;

	if(!data) {
		errno = EFAULT;
		return -1;
	}

	print_packet(utcp, "recv", data, len);

	// Drop packets smaller than the header

	struct hdr hdr;
	if(len < sizeof hdr) {
		errno = EBADMSG;
		return -1;
	}

	// Make a copy from the potentially unaligned data to a struct hdr

	memcpy(&hdr, data, sizeof hdr);
	data += sizeof hdr;
	len -= sizeof hdr;

	// Drop packets with an unknown CTL flag

	if(hdr.ctl & ~(SYN | ACK | RST | FIN)) {
		errno = EBADMSG;
		return -1;
	}

	// Try to match the packet to an existing connection

	struct utcp_connection *c = find_connection(utcp, hdr.dst, hdr.src);

	// Is it for a new connection?

	if(!c) {
		// Ignore RST packets

		if(hdr.ctl & RST)
			return 0;

		// Is it a SYN packet and are we LISTENing?

		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept) {
			// If we don't want to accept it, send a RST back
			if((utcp->pre_accept && !utcp->pre_accept(utcp, hdr.dst))) {
				len = 1;
				goto reset;
			}

			// Try to allocate memory, otherwise send a RST back
			c = allocate_connection(utcp, hdr.dst, hdr.src);
			if(!c) {
				len = 1;
				goto reset;
			}

			// Return SYN+ACK, go to SYN_RECEIVED state
			c->snd.wnd = hdr.wnd;
			c->rcv.irs = hdr.seq;
			c->rcv.nxt = c->rcv.irs + 1;
			set_state(c, SYN_RECEIVED);

			hdr.dst = c->dst;
			hdr.src = c->src;
			hdr.ack = c->rcv.irs + 1;
			hdr.seq = c->snd.iss;
			hdr.ctl = SYN | ACK;
			print_packet(c->utcp, "send", &hdr, sizeof hdr);
			utcp->send(utcp, &hdr, sizeof hdr);
		} else {
			// No, we don't want your packets, send a RST back
			len = 1;
			goto reset;
		}

		return 0;
	}

	debug("%p state %s\n", c->utcp, strstate[c->state]);

	// In case this is for a CLOSED connection, ignore the packet.
	// TODO: make it so incoming packets can never match a CLOSED connection.

	if(c->state == CLOSED)
		return 0;

	// It is for an existing connection.

	uint32_t prevrcvnxt = c->rcv.nxt;

	// 1. Drop invalid packets.

	// 1a. Drop packets that should not happen in our current state.

	switch(c->state) {
	case SYN_SENT:
	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		break;
	default:
#ifdef UTCP_DEBUG
		abort();
#endif
		break;
	}

	// 1b. Drop packets with a sequence number not in our receive window.

	bool acceptable;

	if(c->state == SYN_SENT)
		acceptable = true;
	else if(len == 0)
		acceptable = seqdiff(hdr.seq, c->rcv.nxt) >= 0;
	else {
		int32_t rcv_offset = seqdiff(hdr.seq, c->rcv.nxt);

		// cut already accepted front overlapping
		if(rcv_offset < 0) {
			acceptable = rcv_offset + len >= 0;
			if(acceptable) {
				data -= rcv_offset;
				len += rcv_offset;
			}
		}

		acceptable = seqdiff(hdr.seq, c->rcv.nxt) >= 0 && seqdiff(hdr.seq, c->rcv.nxt) + len <= c->rcvbuf.maxsize;
	}

	if(!acceptable) {
		debug("Packet not acceptable, %u <= %u + %zu < %u\n", c->rcv.nxt, hdr.seq, len, c->rcv.nxt + c->rcvbuf.maxsize);
		// Ignore unacceptable RST packets.
		if(hdr.ctl & RST)
			return 0;
		// Otherwise, send an ACK back in the hope things improve.
		ack(c, true);
		return 0;
	}

	c->snd.wnd = hdr.wnd; // TODO: move below

	// 1c. Drop packets with an invalid ACK.
	// ackno should not roll back, and it should also not be bigger than what we ever could have sent
	// (= snd.una + c->sndbuf.used).

	if(hdr.ctl & ACK && (seqdiff(hdr.ack, c->snd.last) > 0 || seqdiff(hdr.ack, c->snd.una) < 0)) {
		debug("Packet ack seqno out of range, %u <= %u < %u\n", c->snd.una, hdr.ack, c->snd.una + c->sndbuf.used);
		// Ignore unacceptable RST packets.
		if(hdr.ctl & RST)
			return 0;
		goto reset;
	}

	// 2. Handle RST packets

	if(hdr.ctl & RST) {
		switch(c->state) {
		case SYN_SENT:
			if(!(hdr.ctl & ACK))
				return 0;
			// The peer has refused our connection.
			set_state(c, CLOSED);
			errno = ECONNREFUSED;
			if(c->recv)
				c->recv(c, NULL, 0);
			return 0;
		case SYN_RECEIVED:
			if(hdr.ctl & ACK)
				return 0;
			// We haven't told the application about this connection yet. Silently delete.
			free_connection(c);
			return 0;
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
			if(hdr.ctl & ACK)
				return 0;
			// The peer has aborted our connection.
			set_state(c, CLOSED);
			errno = ECONNRESET;
			if(c->recv)
				c->recv(c, NULL, 0);
			return 0;
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			if(hdr.ctl & ACK)
				return 0;
			// As far as the application is concerned, the connection has already been closed.
			// If it has called utcp_close() already, we can immediately free this connection.
			if(c->reapable) {
				free_connection(c);
				return 0;
			}
			// Otherwise, immediately move to the CLOSED state.
			set_state(c, CLOSED);
			return 0;
		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}
	}

	// 3. Advance snd.una

	uint32_t advanced = seqdiff(hdr.ack, c->snd.una);
	prevrcvnxt = c->rcv.nxt;

	if(advanced) {
		// RTT measurement
		if(c->rtt_start.tv_sec) {
			if(c->rtt_seq == hdr.ack) {
				struct timeval now, diff;
				gettimeofday(&now, NULL);
				timersub(&now, &c->rtt_start, &diff);
				update_rtt(c, diff.tv_sec * 1000000 + diff.tv_usec);
				c->rtt_start.tv_sec = 0;
			} else if(c->rtt_seq < hdr.ack) {
				debug("Cancelling RTT measurement: %u < %u\n", c->rtt_seq, hdr.ack);
				c->rtt_start.tv_sec = 0;
			}
		}

		int32_t data_acked = advanced;

		switch(c->state) {
			case SYN_SENT:
			case SYN_RECEIVED:
				data_acked--;
				break;
			// TODO: handle FIN as well.
			default:
				break;
		}

		assert(data_acked >= 0);

		int32_t bufused = seqdiff(c->snd.last, c->snd.una);
		assert(data_acked <= bufused);

		if(data_acked)
			buffer_get(&c->sndbuf, NULL, data_acked);

		// Also advance snd.nxt if possible
		if(seqdiff(c->snd.nxt, hdr.ack) < 0)
			c->snd.nxt = hdr.ack;

		c->snd.una = hdr.ack;

		c->dupack = 0;
		c->snd.cwnd += utcp->mtu;
		if(c->snd.cwnd > c->sndbuf.maxsize)
			c->snd.cwnd = c->sndbuf.maxsize;

		// Check if we have sent a FIN that is now ACKed.
		switch(c->state) {
		case FIN_WAIT_1:
			if(c->snd.una == c->snd.last)
				set_state(c, FIN_WAIT_2);
			break;
		case CLOSING:
			if(c->snd.una == c->snd.last) {
				gettimeofday(&c->conn_timeout, NULL);
				c->conn_timeout.tv_sec += 60;
				set_state(c, TIME_WAIT);
			}
			break;
		default:
			break;
		}
	} else {
		if(!len) {
			c->dupack++;
			if(c->dupack == 3) {
				debug("Triplicate ACK\n");
				//TODO: Resend one packet and go to fast recovery mode. See RFC 6582.
				//We do a very simple variant here; reset the nxt pointer to the last acknowledged packet from the peer.
				//Reset the congestion window so we wait for ACKs.
				c->snd.nxt = c->snd.una;
				c->snd.cwnd = utcp->mtu;
				start_retransmit_timer(c);
			}
		}
	}

	// 4. Update timers

	if(advanced) {
		timerclear(&c->conn_timeout); // It will be set anew in utcp_timeout() if c->snd.una != c->snd.nxt.
		if(c->snd.una == c->snd.last)
			stop_retransmit_timer(c);
		else
			start_retransmit_timer(c);
	}

	// 5. Process SYN stuff

	if(hdr.ctl & SYN) {
		switch(c->state) {
		case SYN_SENT:
			// This is a SYNACK. It should always have ACKed the SYN.
			if(!advanced)
				goto reset;
			c->rcv.irs = hdr.seq;
			c->rcv.nxt = hdr.seq;
			set_state(c, ESTABLISHED);
			// TODO: notify application of this somehow.
			break;
		case SYN_RECEIVED:
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm, no. We should never receive a second SYN.
			goto reset;
		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

		// SYN counts as one sequence number
		c->rcv.nxt++;
	}

	// 6. Process new data

	if(c->state == SYN_RECEIVED) {
		// This is the ACK after the SYNACK. It should always have ACKed the SYNACK.
		if(!advanced)
			goto reset;

		// Are we still LISTENing?
		if(utcp->accept)
			utcp->accept(c, c->src);

		if(c->state != ESTABLISHED) {
			set_state(c, CLOSED);
			c->reapable = true;
			goto reset;
		}
	}

	if(len) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
			break;
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm no, We should never receive more data after a FIN.
			goto reset;
		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			return 0;
		}

		handle_incoming_data(c, hdr.seq, data, len);
	}

	// 7. Process FIN stuff

	if((hdr.ctl & FIN) && hdr.seq + len == c->rcv.nxt) {
		switch(c->state) {
		case SYN_SENT:
		case SYN_RECEIVED:
			// This should never happen.
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		case ESTABLISHED:
			set_state(c, CLOSE_WAIT);
			break;
		case FIN_WAIT_1:
			set_state(c, CLOSING);
			break;
		case FIN_WAIT_2:
			gettimeofday(&c->conn_timeout, NULL);
			c->conn_timeout.tv_sec += 60;
			set_state(c, TIME_WAIT);
			break;
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// Ehm, no. We should never receive a second FIN.
			goto reset;
		default:
#ifdef UTCP_DEBUG
			abort();
#endif
			break;
		}

		// FIN counts as one sequence number
		c->rcv.nxt++;
		len++;

		// Inform the application that the peer closed the connection.
		if(c->recv) {
			errno = 0;
			c->recv(c, NULL, 0);
		}
	}

	// Now we send something back if:
	// - we advanced rcv.nxt (ie, we got some data that needs to be ACKed)
	//   -> sendatleastone = true
	// - or we got an ack, so we should maybe send a bit more data
	//   -> sendatleastone = false

	ack(c, len || prevrcvnxt != c->rcv.nxt);
	return 0;

reset:
	swap_ports(&hdr);
	hdr.wnd = 0;
	if(hdr.ctl & ACK) {
		hdr.seq = hdr.ack;
		hdr.ctl = RST;
	} else {
		hdr.ack = hdr.seq + len;
		hdr.seq = 0;
		hdr.ctl = RST | ACK;
	}
	print_packet(utcp, "send", &hdr, sizeof hdr);
	utcp->send(utcp, &hdr, sizeof hdr);
	return 0;

}

int utcp_shutdown(struct utcp_connection *c, int dir) {
	debug("%p shutdown %d at %u\n", c ? c->utcp : NULL, dir, c ? c->snd.last : 0);
	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		debug("Error: shutdown() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	if(!(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_WR || dir == UTCP_SHUT_RDWR)) {
		errno = EINVAL;
		return -1;
	}

	// TCP does not have a provision for stopping incoming packets.
	// The best we can do is to just ignore them.
	if(dir == UTCP_SHUT_RD || dir == UTCP_SHUT_RDWR)
		c->recv = NULL;

	// The rest of the code deals with shutting down writes.
	if(dir == UTCP_SHUT_RD)
		return 0;

	switch(c->state) {
	case CLOSED:
	case LISTEN:
		errno = ENOTCONN;
		return -1;

	case SYN_SENT:
		set_state(c, CLOSED);
		return 0;

	case SYN_RECEIVED:
	case ESTABLISHED:
		set_state(c, FIN_WAIT_1);
		break;
	case FIN_WAIT_1:
	case FIN_WAIT_2:
		return 0;
	case CLOSE_WAIT:
		set_state(c, CLOSING);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		return 0;
	}

	c->snd.last++;

	ack(c, false);
	if(!timerisset(&c->rtrx_timeout))
		start_retransmit_timer(c);
	return 0;
}

int utcp_close(struct utcp_connection *c) {
	if(utcp_shutdown(c, SHUT_RDWR))
		return -1;
	c->recv = NULL;
	c->poll = NULL;
	c->reapable = true;
	return 0;
}

int utcp_abort(struct utcp_connection *c) {
	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		debug("Error: abort() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	c->recv = NULL;
	c->poll = NULL;
	c->reapable = true;

	switch(c->state) {
	case CLOSED:
		return 0;
	case LISTEN:
	case SYN_SENT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		set_state(c, CLOSED);
		return 0;

	case SYN_RECEIVED:
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
	case CLOSE_WAIT:
		set_state(c, CLOSED);
		break;
	}

	// Send RST

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.nxt;
	hdr.ack = 0;
	hdr.wnd = 0;
	hdr.ctl = RST;

	print_packet(c->utcp, "send", &hdr, sizeof hdr);
	c->utcp->send(c->utcp, &hdr, sizeof hdr);
	return 0;
}

/* Handle timeouts.
 * One call to this function will loop through all connections,
 * checking if something needs to be resent or not.
 * The return value is the time to the next timeout in milliseconds,
 * or maybe a negative value if the timeout is infinite.
 */
struct timeval utcp_timeout(struct utcp *utcp) {
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval next = {now.tv_sec + 3600, now.tv_usec};

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];
		if(!c)
			continue;

		// delete connections that have been utcp_close()d.
		if(c->state == CLOSED) {
			if(c->reapable) {
				debug("Reaping %p\n", c);
				free_connection(c);
				i--;
			}
			continue;
		}

		if(timerisset(&c->conn_timeout) && timercmp(&c->conn_timeout, &now, <)) {
			errno = ETIMEDOUT;
			c->state = CLOSED;
			if(c->recv)
				c->recv(c, NULL, 0);
			continue;
		}

		if(timerisset(&c->rtrx_timeout) && timercmp(&c->rtrx_timeout, &now, <)) {
			debug("retransmit()\n");
			retransmit(c);
		}

		if(c->poll && buffer_free(&c->sndbuf) && (c->state == ESTABLISHED || c->state == CLOSE_WAIT))
			c->poll(c, buffer_free(&c->sndbuf));

		if(timerisset(&c->conn_timeout) && timercmp(&c->conn_timeout, &next, <))
			next = c->conn_timeout;

		if(timerisset(&c->rtrx_timeout) && timercmp(&c->rtrx_timeout, &next, <))
			next = c->rtrx_timeout;
	}

	struct timeval diff;
	timersub(&next, &now, &diff);
	return diff;
}

bool utcp_is_active(struct utcp *utcp) {
	if(!utcp)
		return false;

	for(int i = 0; i < utcp->nconnections; i++)
		if(utcp->connections[i]->state != CLOSED && utcp->connections[i]->state != TIME_WAIT)
			return true;

	return false;
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv) {
	if(!send) {
		errno = EFAULT;
		return NULL;
	}

	struct utcp *utcp = calloc(1, sizeof *utcp);
	if(!utcp)
		return NULL;

	utcp->accept = accept;
	utcp->pre_accept = pre_accept;
	utcp->send = send;
	utcp->priv = priv;
	utcp->mtu = DEFAULT_MTU;
	utcp->timeout = DEFAULT_USER_TIMEOUT; // s
	utcp->rto = START_RTO; // us

	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	if(!utcp)
		return;
	for(int i = 0; i < utcp->nconnections; i++) {
		if(!utcp->connections[i]->reapable)
			debug("Warning, freeing unclosed connection %p\n", utcp->connections[i]);
		buffer_exit(&utcp->connections[i]->rcvbuf);
		buffer_exit(&utcp->connections[i]->sndbuf);
		free(utcp->connections[i]);
	}
	free(utcp->connections);
	free(utcp);
}

uint16_t utcp_get_mtu(struct utcp *utcp) {
	return utcp ? utcp->mtu : 0;
}

void utcp_set_mtu(struct utcp *utcp, uint16_t mtu) {
	// TODO: handle overhead of the header
	if(utcp)
		utcp->mtu = mtu;
}

int utcp_get_user_timeout(struct utcp *u) {
	return u ? u->timeout : 0;
}

void utcp_set_user_timeout(struct utcp *u, int timeout) {
	if(u)
		u->timeout = timeout;
}

size_t utcp_get_sndbuf(struct utcp_connection *c) {
	return c ? c->sndbuf.maxsize : 0;
}

size_t utcp_get_sndbuf_free(struct utcp_connection *c) {
	if(c && (c->state == ESTABLISHED || c->state == CLOSE_WAIT))
		return buffer_free(&c->sndbuf);
	else
		return 0;
}

void utcp_set_sndbuf(struct utcp_connection *c, size_t size) {
	if(!c)
		return;
	c->sndbuf.maxsize = size;
	if(c->sndbuf.maxsize != size)
		c->sndbuf.maxsize = -1;
}

size_t utcp_get_rcvbuf(struct utcp_connection *c) {
	return c ? c->rcvbuf.maxsize : 0;
}

size_t utcp_get_rcvbuf_free(struct utcp_connection *c) {
	if(c && (c->state == ESTABLISHED || c->state == CLOSE_WAIT))
		return buffer_free(&c->rcvbuf);
	else
		return 0;
}

void utcp_set_rcvbuf(struct utcp_connection *c, size_t size) {
	if(!c)
		return;
	c->rcvbuf.maxsize = size;
	if(c->rcvbuf.maxsize != size)
		c->rcvbuf.maxsize = -1;
}

bool utcp_get_nodelay(struct utcp_connection *c) {
	return c ? c->nodelay : false;
}

void utcp_set_nodelay(struct utcp_connection *c, bool nodelay) {
	if(c)
		c->nodelay = nodelay;
}

bool utcp_get_keepalive(struct utcp_connection *c) {
	return c ? c->keepalive : false;
}

void utcp_set_keepalive(struct utcp_connection *c, bool keepalive) {
	if(c)
		c->keepalive = keepalive;
}

size_t utcp_get_outq(struct utcp_connection *c) {
	return c ? seqdiff(c->snd.nxt, c->snd.una) : 0;
}

void utcp_set_recv_cb(struct utcp_connection *c, utcp_recv_t recv) {
	if(c)
		c->recv = recv;
}

void utcp_set_poll_cb(struct utcp_connection *c, utcp_poll_t poll) {
	if(c)
		c->poll = poll;
}

void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_pre_accept_t pre_accept) {
	if(utcp) {
		utcp->accept = accept;
		utcp->pre_accept = pre_accept;
	}
}
