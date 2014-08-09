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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>

#define UTCP_INTERNAL
#include "utcp.h"

#define PREP(l) char pkt[(l) + sizeof struct hdr]; struct hdr *hdr = &pkt;

#define SYN 1
#define ACK 2
#define FIN 4
#define RST 8

struct hdr {
	uint16_t src; // Source port
	uint16_t dst; // Destination port
	uint32_t seq; // Sequence number
	uint32_t ack; // Acknowledgement number
	uint32_t wnd; // Window size
	uint16_t ctl; // Flags (SYN, ACK, FIN, RST)
	uint16_t aux; // other stuff
};

enum state {
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECEIVED,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSE_WAIT,
	CLOSING,
	LAST_ACK,
	TIME_WAIT
};

const char *strstate[] = {
	"CLOSED",
	"LISTEN",
	"SYN_SENT",
	"SYN_RECEIVED",
	"ESTABLISHED",
	"FIN_WAIT_1",
	"FIN_WAIT_2",
	"CLOSE_WAIT",
	"CLOSING",
	"LAST_ACK",
	"TIME_WAIT"
};

struct utcp_connection {
	void *priv;
	struct utcp *utcp;
	bool reapable;

	uint16_t src;
	uint16_t dst;
	enum state state;

	// The following two structures form the TCB

	struct {
		uint32_t una;
		uint32_t nxt;
		uint32_t wnd;
		uint32_t up;
		uint32_t wl1;
		uint32_t wl2;
		uint32_t iss;
	} snd;

	struct {
		uint32_t nxt;
		uint32_t wnd;
		uint32_t up;
		uint32_t irs;
	} rcv;

	utcp_recv_t recv;

	struct timeval conn_timeout;
	struct timeval rtrx_timeout;

	char *sndbuf;
	uint32_t sndbufsize;
};

struct utcp {
	void *priv;

	utcp_accept_t accept;
	utcp_pre_accept_t pre_accept;
	utcp_send_t send;

	uint16_t mtu;
	int timeout;

	struct utcp_connection **connections;
	int nconnections;
	int nallocated;
};

static void set_state(struct utcp_connection *c, enum state state) {
	c->state = state;
	if(state == ESTABLISHED)
		timerclear(&c->conn_timeout);
	fprintf(stderr, "%p new state: %s\n", c->utcp, strstate[state]);
}

static void print_packet(const void *pkt, size_t len) {
	struct hdr hdr;
	if(len < sizeof hdr) {
		fprintf(stderr, "short packet (%zu bytes)\n", len);
		return;
	}

	memcpy(&hdr, pkt, sizeof hdr);
	fprintf (stderr, "src=%u dst=%u seq=%u ack=%u wnd=%u ctl=", hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.wnd);
	if(hdr.ctl & SYN)
		fprintf(stderr, "SYN");
	if(hdr.ctl & RST)
		fprintf(stderr, "RST");
	if(hdr.ctl & FIN)
		fprintf(stderr, "FIN");
	if(hdr.ctl & ACK)
		fprintf(stderr, "ACK");

	if(len > sizeof hdr) {
		fprintf(stderr, " data=");
		for(int i = sizeof hdr; i < len; i++) {
			const char *data = pkt;
			fprintf(stderr, "%c", data[i] >= 32 ? data[i] : '.');
		}
	}

	fprintf(stderr, "\n");
}

static inline void list_connections(struct utcp *utcp) {
	fprintf(stderr, "%p has %d connections:\n", utcp, utcp->nconnections);
	for(int i = 0; i < utcp->nconnections; i++)
		fprintf(stderr, "  %u -> %u state %s\n", utcp->connections[i]->src, utcp->connections[i]->dst, strstate[utcp->connections[i]->state]);
}

// Connections are stored in a sorted list.
// This gives O(log(N)) lookup time, O(N log(N)) insertion time and O(N) deletion time.

static int compare(const void *va, const void *vb) {
	const struct utcp_connection *a = *(struct utcp_connection **)va;
	const struct utcp_connection *b = *(struct utcp_connection **)vb;
	if(!a->src || !b->src)
		abort();
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
	if(!cp)
		abort();

	int i = cp - utcp->connections;
	memmove(cp + i, cp + i + 1, (utcp->nconnections - i - 1) * sizeof *cp);
	utcp->nconnections--;

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
		if(!new_array) {
			errno = ENOMEM;
			return NULL;
		}
		utcp->connections = new_array;
	}

	struct utcp_connection *c = calloc(1, sizeof *c);
	if(!c) {
		errno = ENOMEM;
		return NULL;
	}

	// Fill in the details

	c->src = src;
	c->dst = dst;
	c->snd.iss = rand();
	c->snd.una = c->snd.iss;
	c->snd.nxt = c->snd.iss + 1;
	c->rcv.wnd = utcp->mtu;
	c->utcp = utcp;
	c->sndbufsize = 65536;
	c->sndbuf = malloc(c->sndbufsize);
	if(!c->sndbuf)
		c->sndbufsize = 0;

	// Add it to the sorted list of connections

	utcp->connections[utcp->nconnections++] = c;
	qsort(utcp->connections, utcp->nconnections, sizeof *utcp->connections, compare);

	return c;
}

struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t dst, utcp_recv_t recv, void *priv) {
	struct utcp_connection *c = allocate_connection(utcp, 0, dst);
	if(!c)
		return NULL;

	c->recv = recv;

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.iss;
	hdr.ack = 0;
	hdr.ctl = SYN;
	hdr.wnd = c->rcv.wnd;

	set_state(c, SYN_SENT);

	utcp->send(utcp, &hdr, sizeof hdr);

	gettimeofday(&c->conn_timeout, NULL);
	c->conn_timeout.tv_sec += utcp->timeout;

	return c;
}

void utcp_accept(struct utcp_connection *c, utcp_recv_t recv, void *priv) {
	if(c->reapable || c->state != SYN_RECEIVED) {
		fprintf(stderr, "Error: accept() called on invalid connection %p in state %s\n", c, strstate[c->state]);
		return;
	}

	fprintf(stderr, "%p accepted, %p %p\n", c, recv, priv);
	c->recv = recv;
	c->priv = priv;
	set_state(c, ESTABLISHED);
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
	if(c->reapable) {
		fprintf(stderr, "Error: send() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	switch(c->state) {
	case CLOSED:
	case LISTEN:
	case SYN_SENT:
	case SYN_RECEIVED:
		fprintf(stderr, "Error: send() called on unconnected connection %p\n", c);
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
		fprintf(stderr, "Error: send() called on closing connection %p\n", c);
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

	uint32_t bufused = c->snd.nxt - c->snd.una;

	if(len > c->sndbufsize - bufused)
		len = c->sndbufsize - bufused;

	memcpy(c->sndbuf + (c->snd.nxt - c->snd.una), data, len);

	// Send segments

	struct {
		struct hdr hdr;
		char data[c->utcp->mtu];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = c->dst;
	pkt.hdr.ack = c->rcv.nxt;
	pkt.hdr.wnd = c->snd.wnd;
	pkt.hdr.ctl = ACK;

	uint32_t left = len;

	while(left) {
		uint32_t seglen = left > c->utcp->mtu ? c->utcp->mtu : left;
		pkt.hdr.seq = c->snd.nxt;

		memcpy(pkt.data, data, seglen);

		c->snd.nxt += seglen;
		data += seglen;
		left -= seglen;

		c->utcp->send(c->utcp, &pkt, sizeof pkt.hdr + seglen);
	}

	fprintf(stderr, "len=%zu\n", len);
	return len;
}

static void swap_ports(struct hdr *hdr) {
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

static int32_t seqdiff(uint32_t a, uint32_t b) {
	return a - b;
}

int utcp_recv(struct utcp *utcp, const void *data, size_t len) {
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

	fprintf(stderr, "%p got: ", utcp);
	print_packet(data, len);

	struct hdr hdr;
	if(len < sizeof hdr) {
		errno = EBADMSG;
		return -1;
	}

	memcpy(&hdr, data, sizeof hdr);
	data += sizeof hdr;
	len -= sizeof hdr;

	if(hdr.ctl & ~(SYN | ACK | RST | FIN)) {
		errno = EBADMSG;
		return -1;
	}

	//list_connections(utcp);

	struct utcp_connection *c = find_connection(utcp, hdr.dst, hdr.src);

	// Is it for a new connection?

	if(!c) {
		if(hdr.ctl & RST)
			return 0;

		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept && (!utcp->pre_accept || utcp->pre_accept(utcp, hdr.dst)) && (c = allocate_connection(utcp, hdr.dst, hdr.src))) { // LISTEN
			// Return SYN+ACK
			c->snd.wnd = hdr.wnd;
			c->rcv.irs = hdr.seq;
			c->rcv.nxt = c->rcv.irs + 1;
			set_state(c, SYN_RECEIVED);

			hdr.dst = c->dst;
			hdr.src = c->src;
			hdr.ack = c->rcv.irs + 1;
			hdr.seq = c->snd.iss;
			hdr.ctl = SYN | ACK;
			utcp->send(utcp, &hdr, sizeof hdr);
			return 0;
		} else { // CLOSED
			len = 1;
			goto reset;
		}
	}

	fprintf(stderr, "%p state %s\n", c->utcp, strstate[c->state]);

	if(c->state == CLOSED) {
		fprintf(stderr, "Error: packet recv()d on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	// It is for an existing connection.

	if(c->state == SYN_SENT) {
		if(hdr.ctl & ACK) {
			if(seqdiff(hdr.ack, c->snd.iss) <= 0 || seqdiff(hdr.ack, c->snd.nxt) > 0) {
				fprintf(stderr, "Invalid ACK, %u %u %u\n", hdr.ack, c->snd.iss, c->snd.nxt);
				goto reset;
			}
		}
		if(hdr.ctl & RST) {
			if(!(hdr.ctl & ACK))
				return 0;
			set_state(c, CLOSED);
			errno = ECONNREFUSED;
			if(c->recv)
				c->recv(c, NULL, 0);
			return 0;
		}
		if(hdr.ctl & SYN) {
			c->dst = hdr.src;
			c->rcv.nxt = hdr.seq + 1;
			c->rcv.irs = hdr.seq;
			c->snd.wnd = hdr.wnd;

			if(hdr.ctl & ACK)
				c->snd.una = hdr.ack;
			if(seqdiff(c->snd.una, c->snd.iss) > 0) {
				set_state(c, ESTABLISHED);
				// TODO: signal app?
				swap_ports(&hdr);
				hdr.seq = c->snd.nxt;
				hdr.ack = c->rcv.nxt;
				hdr.ctl = ACK;
			} else {
				set_state(c, SYN_RECEIVED);
				swap_ports(&hdr);
				hdr.seq = c->snd.iss;
				hdr.ack = c->rcv.nxt;
				hdr.ctl = SYN | ACK;
			}
			utcp->send(utcp, &hdr, sizeof hdr);
			// TODO: queue any data?
		}

		return 0;
	}

	bool acceptable;

	if(len == 0)
		if(c->rcv.wnd == 0)
			acceptable = hdr.seq == c->rcv.nxt;
		else
			acceptable = (hdr.seq >= c->rcv.nxt && hdr.seq < c->rcv.nxt + c->rcv.wnd);
	else
		if(c->rcv.wnd == 0)
			acceptable = false;
		else
			acceptable = (hdr.seq >= c->rcv.nxt && hdr.seq < c->rcv.nxt + c->rcv.wnd)
				|| (hdr.seq + len - 1 >= c->rcv.nxt && hdr.seq + len - 1 < c->rcv.nxt + c->rcv.wnd);

	if(!acceptable) {
		fprintf(stderr, "Packet not acceptable, %u %u %u %zu\n", hdr.seq, c->rcv.nxt, c->rcv.wnd, len);
		if(hdr.ctl & RST)
			return 0;
		goto ack_and_drop;
	}

	c->snd.wnd = hdr.wnd;

	// TODO: check whether segment really starts at rcv.nxt, otherwise trim it.

	if(hdr.ctl & RST) {
		switch(c->state) {
		case SYN_RECEIVED:
			// TODO: delete connection?
			break;
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
			set_state(c, CLOSED);
			errno = ECONNRESET;
			if(c->recv)
				c->recv(c, NULL, 0);
			break;
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			// TODO: delete connection?
			break;
		default:
			// TODO: wtf?
			return 0;
		}
		set_state(c, CLOSED);
		return 0;
	}

	if(hdr.ctl & SYN) {
		switch(c->state) {
		case SYN_RECEIVED:
		case ESTABLISHED:
		case FIN_WAIT_1:
		case FIN_WAIT_2:
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			set_state(c, CLOSED);
			errno = ECONNRESET;
			if(c->recv)
				c->recv(c, NULL, 0);
			goto reset;
			break;
		default:
			// TODO: wtf?
			return 0;
		}
	}

	if(!(hdr.ctl & ACK))
		return 0;

	switch(c->state) {
	case SYN_RECEIVED:
		if(seqdiff(hdr.ack, c->snd.una) >= 0 && seqdiff(hdr.ack, c->snd.nxt) <= 0)
			c->utcp->accept(c, hdr.dst);
		
		if(c->state != ESTABLISHED)
			goto reset;
		break;
	case ESTABLISHED:
	case CLOSE_WAIT:
		if(seqdiff(hdr.ack, c->snd.una) < 0)
			return 0;
		if(seqdiff(hdr.ack, c->snd.nxt) > 0)
			goto ack_and_drop;
		if(seqdiff(hdr.ack, c->snd.una) > 0 && seqdiff(hdr.ack, c->snd.nxt) <= 0) {
			c->snd.una = hdr.ack;
			if(seqdiff(c->snd.wl1, hdr.seq) < 0 || (c->snd.wl1 == hdr.seq && seqdiff(c->snd.wl2, hdr.ack) <= 0)) {
				c->snd.wnd = hdr.wnd;
				c->snd.wl1 = hdr.seq;
				c->snd.wl2 = hdr.ack;
			}
		}
		break;
	case FIN_WAIT_1:
		if(hdr.ack == c->snd.nxt)
			set_state(c, FIN_WAIT_2);
		break;
	case FIN_WAIT_2:
		// TODO: If nothing left to send, close.
		break;
	case CLOSING:
		if(hdr.ack == c->snd.nxt) {
			set_state(c, TIME_WAIT);
		}
		break;
	case LAST_ACK:
		if(hdr.ack == c->snd.nxt) {
			set_state(c, CLOSED);
		}
		return 0;
	case TIME_WAIT:
		// TODO: retransmission of remote FIN, ACK and restart 2 MSL timeout
		break;
	default:
		goto reset;
	}

	// Process data

	switch(c->state) {
	case ESTABLISHED:
	case FIN_WAIT_1:
	case FIN_WAIT_2:
		// TODO: process the data, see page 74
		break;
	case CLOSE_WAIT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		break;
	default:
		abort();
	}

	if(hdr.ctl & FIN) {
		switch(c->state) {
		case CLOSED:
		case LISTEN:
		case SYN_SENT:
			return 0;
		case SYN_RECEIVED:
		case ESTABLISHED:
			set_state(c, CLOSE_WAIT);
			c->rcv.nxt++;
			goto ack_and_drop;
		case FIN_WAIT_1:
			set_state(c, CLOSING);
			c->rcv.nxt++;
			goto ack_and_drop;
		case FIN_WAIT_2:
			set_state(c, TIME_WAIT);
			c->rcv.nxt++;
			goto ack_and_drop;
		case CLOSE_WAIT:
		case CLOSING:
		case LAST_ACK:
		case TIME_WAIT:
			break;
		default:
			abort();
		}
	}

	// Process the data

	if(len && c->recv) {
		c->recv(c, data, len);
		c->rcv.nxt += len;
		goto ack_and_drop;
	}

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
	utcp->send(utcp, &hdr, sizeof hdr);
	return 0;

ack_and_drop:
	swap_ports(&hdr);
	hdr.seq = c->snd.nxt;
	hdr.ack = c->rcv.nxt;
	hdr.ctl = ACK;
	utcp->send(utcp, &hdr, sizeof hdr);
	if(c->state == CLOSE_WAIT || c->state == TIME_WAIT) {
		errno = 0;
		if(c->recv)
			c->recv(c, NULL, 0);
	}
	return 0;
}

int utcp_shutdown(struct utcp_connection *c, int dir) {
	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		fprintf(stderr, "Error: shutdown() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

	// TODO: handle dir

	switch(c->state) {
	case CLOSED:
		return 0;
	case LISTEN:
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
		set_state(c, LAST_ACK);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		return 0;
	}

	// Send FIN

	struct hdr hdr;

	hdr.src = c->src;
	hdr.dst = c->dst;
	hdr.seq = c->snd.nxt;
	hdr.ack = c->rcv.nxt;
	hdr.wnd = c->snd.wnd;
	hdr.ctl = FIN | ACK;

	c->snd.nxt += 1;

	c->utcp->send(c->utcp, &hdr, sizeof hdr);
	return 0;
}

int utcp_close(struct utcp_connection *c) {
	if(utcp_shutdown(c, SHUT_RDWR))
		return -1;
	c->reapable = true;
	return 0;
}

int utcp_abort(struct utcp_connection *c) {
	if(!c) {
		errno = EFAULT;
		return -1;
	}

	if(c->reapable) {
		fprintf(stderr, "Error: abort() called on closed connection %p\n", c);
		errno = EBADF;
		return -1;
	}

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

	c->utcp->send(c->utcp, &hdr, sizeof hdr);
	return 0;
}

static void retransmit(struct utcp_connection *c) {
	if(c->state == CLOSED || c->snd.nxt == c->snd.una)
		return;

	struct utcp *utcp = c->utcp;

	struct {
		struct hdr hdr;
		char data[c->utcp->mtu];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = c->dst;

	switch(c->state) {
		case LISTEN:
			// TODO: this should not happen
			break;

		case SYN_SENT:
			pkt.hdr.seq = c->snd.iss;
			pkt.hdr.ack = 0;
			pkt.hdr.wnd = c->rcv.wnd;
			pkt.hdr.ctl = SYN;
			utcp->send(utcp, &pkt, sizeof pkt.hdr);
			break;

		case SYN_RECEIVED:
			pkt.hdr.seq = c->snd.nxt;
			pkt.hdr.ack = c->rcv.nxt;
			pkt.hdr.ctl = SYN | ACK;
			utcp->send(utcp, &pkt, sizeof pkt.hdr);
			break;

		case ESTABLISHED:
			pkt.hdr.seq = c->snd.una;
			pkt.hdr.ack = c->rcv.nxt;
			pkt.hdr.ctl = ACK;
			uint32_t len = seqdiff(c->snd.nxt, c->snd.una);
			if(len > utcp->mtu)
				len = utcp->mtu;
			memcpy(pkt.data, c->sndbuf, len);
			utcp->send(utcp, &pkt, sizeof pkt.hdr + len);
			break;

		default:
			// TODO: implement
			abort();
	}
}

/* Handle timeouts.
 * One call to this function will loop through all connections,
 * checking if something needs to be resent or not.
 * The return value is the time to the next timeout in milliseconds,
 * or maybe a negative value if the timeout is infinite.
 */
int utcp_timeout(struct utcp *utcp) {
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval next = {now.tv_sec + 3600, now.tv_usec};

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];
		if(!c)
			continue;

		if(c->state == CLOSED) {
			if(c->reapable) {
				fprintf(stderr, "Reaping %p\n", c);
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
			retransmit(c);
		}

		if(timerisset(&c->conn_timeout) && timercmp(&c->conn_timeout, &next, <))
			next = c->conn_timeout;

		if(c->snd.nxt != c->snd.una) {
			c->rtrx_timeout = now;
			c->rtrx_timeout.tv_sec++;
		} else {
			timerclear(&c->rtrx_timeout);
		}

		if(timerisset(&c->rtrx_timeout) && timercmp(&c->rtrx_timeout, &next, <))
			next = c->rtrx_timeout;
	}

	struct timeval diff;
	timersub(&next, &now, &diff);
	if(diff.tv_sec < 0)
		return 0;
	return diff.tv_sec * 1000 + diff.tv_usec / 1000;
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv) {
	struct utcp *utcp = calloc(1, sizeof *utcp);
	if(!utcp)
		return NULL;

	if(!send) {
		errno = EFAULT;
		return NULL;
	}

	utcp->accept = accept;
	utcp->pre_accept = pre_accept;
	utcp->send = send;
	utcp->priv = priv;
	utcp->mtu = 1000;
	utcp->timeout = 60;

	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	if(!utcp)
		return;
	for(int i = 0; i < utcp->nconnections; i++)
		free_connection(utcp->connections[i]);
	free(utcp);
}

int utcp_set_connection_timeout(struct utcp *u, int timeout) {
	int prev = u->timeout;
	u->timeout = timeout;
	return prev;
}
