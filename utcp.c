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
};

struct utcp {
	void *priv;

	utcp_accept_t accept;
	utcp_pre_accept_t pre_accept;
	utcp_send_t send;

	uint16_t mtu;

	struct utcp_connection **connections;
	int nconnections;
	int nallocated;
	int gap;
};

static void set_state(struct utcp_connection *c, enum state state) {
	c->state = state;
	fprintf(stderr, "%p new state: %s\n", c->utcp, strstate[state]);
}

static void print_packet(void *pkt, size_t len) {
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
			char *data = pkt;
			fprintf(stderr, "%c", data[i] >= 32 ? data[i] : '.');
		}
	}

	fprintf(stderr, "\n");
}

static struct utcp_connection *allocate_connection(struct utcp *utcp) {
	struct utcp_connection *c;

	// Initial allocation?

	if(!utcp->nconnections) {
		utcp->nallocated = 4;
		utcp->nconnections = 1; // Skip 0
		utcp->connections = calloc(utcp->nallocated, sizeof *utcp->connections);
	}

	// If there is a hole in the list of connections, use it.
	// Otherwise, add a new connection to the end.

	if(utcp->gap >= 0) {
		c = utcp->connections[utcp->gap] = calloc(1, sizeof *c);
		c->src = utcp->gap;
		while(++utcp->gap < utcp->nconnections)
			if(!utcp->connections[utcp->gap])
				break;

		if(utcp->gap >= utcp->nconnections)
			utcp->gap = -1;
	} else {
		// Too many connections?

		if(utcp->nconnections >= 65536) {
			errno = ENOMEM;
			return NULL;
		}

		// Need to reserve more memory?

		if(utcp->nconnections >= utcp->nallocated) {
			utcp->nallocated *= 2;
			utcp->connections = realloc(utcp->connections, utcp->nallocated * sizeof *utcp->connections);
		}

		c = utcp->connections[utcp->nconnections] = calloc(1, sizeof *c);
		c->src = utcp->nconnections++;
	}

	c->snd.iss = rand();
	c->snd.una = c->snd.iss;
	c->snd.nxt = c->snd.iss + 1;
	c->rcv.wnd = utcp->mtu;
	c->utcp = utcp;
	return c;
}

static struct utcp_connection *find_connection(struct utcp *utcp, uint16_t src) {
	if(src < utcp->nconnections && utcp->connections[src])
		return utcp->connections[src];

	errno = EINVAL;
	return NULL;
}

static void free_connection(struct utcp_connection *c) {
	if(!c)
		return;
	if(c->utcp->gap < 0 || c->src < c->utcp->gap)
		c->utcp->gap = c->src;
	c->utcp->connections[c->src] = NULL;
	free(c);
}

struct utcp_connection *utcp_connect(struct utcp *utcp, void *data, size_t len, utcp_recv_t recv, void *priv) {
	struct utcp_connection *c = allocate_connection(utcp);
	if(!c)
		return NULL;

	c->recv = recv;

	struct {
		struct hdr hdr;
		char data[len];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = 0;
	pkt.hdr.seq = c->snd.iss;
	pkt.hdr.ack = 0;
	pkt.hdr.ctl = SYN;
	pkt.hdr.wnd = c->rcv.wnd;
	memcpy(pkt.data, data, len);

	set_state(c, SYN_SENT);

	utcp->send(utcp, &pkt, sizeof pkt.hdr + len);

	// Set timeout?

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

int utcp_send(struct utcp_connection *c, void *data, size_t len) {
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
	
	struct {
		struct hdr hdr;
		char data[len];
	} pkt;

	pkt.hdr.src = c->src;
	pkt.hdr.dst = c->dst;
	pkt.hdr.seq = c->snd.nxt;
	pkt.hdr.ack = c->rcv.nxt;
	pkt.hdr.wnd = c->snd.wnd;
	pkt.hdr.ctl = ACK;

	memcpy(pkt.data, data, len);

	c->snd.nxt += len;

	c->utcp->send(c->utcp, &pkt, sizeof pkt.hdr + len);
	//
	// Can we add it to the send window?
	
	// Do we need to kick some timers?
	
	return 0;
}

static void swap_ports(struct hdr *hdr) {
	uint16_t tmp = hdr->src;
	hdr->src = hdr->dst;
	hdr->dst = tmp;
}

int utcp_recv(struct utcp *utcp, void *data, size_t len) {
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

	struct utcp_connection *c = find_connection(utcp, hdr.dst);

	// Is it for a new connection?

	if(!c) {
		if(hdr.ctl & RST)
			return 0;

		if(hdr.ctl & SYN && !(hdr.ctl & ACK) && utcp->accept && (!utcp->pre_accept || utcp->pre_accept(utcp, data, len)) && (c = allocate_connection(utcp))) { // LISTEN
			// Return SYN+ACK
			c->snd.wnd = hdr.wnd;
			c->rcv.irs = hdr.seq;
			c->snd.iss = rand();
			c->snd.una = c->snd.iss;
			c->snd.nxt = c->snd.iss + 1;
			c->rcv.nxt = c->rcv.irs + 1;
			set_state(c, SYN_RECEIVED);

			hdr.dst = c->dst = hdr.src;
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
			if(hdr.ack <= c->snd.iss || hdr.ack > c->snd.nxt) {
				fprintf(stderr, "Invalid ACK, %u %u %u\n", hdr.ack, c->snd.iss, c->snd.nxt);
				goto reset;
			}
		}
		if(hdr.ctl & RST) {
			if(!(hdr.ctl & ACK))
				return 0;
			set_state(c, CLOSED);
			errno = ECONNREFUSED;
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
			if(c->snd.una > c->snd.iss) {
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
		if(hdr.ack >= c->snd.una && hdr.ack <= c->snd.nxt)
			c->utcp->accept(c, NULL, 0);
		
		if(c->state != ESTABLISHED)
			goto reset;
		break;
	case ESTABLISHED:
	case CLOSE_WAIT:
		if(hdr.ack < c->snd.una)
			return 0;
		if(hdr.ack > c->snd.nxt)
			goto ack_and_drop;
		if(hdr.ack > c->snd.una && hdr.ack <= c->snd.nxt) {
			c->snd.una = hdr.ack;
			if(c->snd.wl1 < hdr.seq || (c->snd.wl1 == hdr.seq && c->snd.wl2 <= hdr.ack)) {
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
		c->recv(c, NULL, 0);
	}
	return 0;
}

void utcp_shutdown(struct utcp_connection *c, int dir) {
	if(c->reapable) {
		fprintf(stderr, "Error: shutdown() called on closed connection %p\n", c);
		return;
	}

	// TODO: handle dir

	switch(c->state) {
	case CLOSED:
		return;
	case LISTEN:
	case SYN_SENT:
		set_state(c, CLOSED);
		return;

	case SYN_RECEIVED:
	case ESTABLISHED:
		set_state(c, FIN_WAIT_1);
		break;
	case FIN_WAIT_1:
	case FIN_WAIT_2:
		return;
	case CLOSE_WAIT:
		set_state(c, LAST_ACK);
		break;

	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		return;
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
}

void utcp_close(struct utcp_connection *c) {
	utcp_shutdown(c, SHUT_RDWR);
	c->reapable = true;
}

void utcp_abort(struct utcp_connection *c) {
	if(c->reapable) {
		fprintf(stderr, "Error: abort() called on closed connection %p\n", c);
		return;
	}

	c->reapable = true;

	switch(c->state) {
	case CLOSED:
		return;
	case LISTEN:
	case SYN_SENT:
	case CLOSING:
	case LAST_ACK:
	case TIME_WAIT:
		set_state(c, CLOSED);
		return;

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
}

void utcp_timeout(struct utcp *utcp) {
	struct timeval now;
	gettimeofday(&now, NULL);

	for(int i = 0; i < utcp->nconnections; i++) {
		struct utcp_connection *c = utcp->connections[i];
		if(!c)
			continue;

		if(c->reapable) {
			fprintf(stderr, "Reaping %p\n", c);
			free_connection(c);
			continue;
		}

		if(c->state == CLOSED)
			return;

		if(c->conn_timeout.tv_sec && timercmp(&c->conn_timeout, &now, <)) {
			if(!c->reapable) {
				errno = ETIMEDOUT;
				c->recv(c, NULL, 0);
			}
			c->state = CLOSED;
			return;
		}

		if(c->rtrx_timeout.tv_sec && timercmp(&c->rtrx_timeout, &now, <)) {
			// TODO: retransmit stuff;
		}
	}
}

struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv) {
	struct utcp *utcp = calloc(1, sizeof *utcp);
	if(!utcp)
		return NULL;

	utcp->accept = accept;
	utcp->pre_accept = pre_accept;
	utcp->send = send;
	utcp->priv = priv;
	utcp->gap = -1;
	utcp->mtu = 1000;

	return utcp;
}

void utcp_exit(struct utcp *utcp) {
	if(!utcp)
		return;
	for(int i = 0; i < utcp->nconnections; i++)
		free_connection(utcp->connections[i]);
	free(utcp);
}
