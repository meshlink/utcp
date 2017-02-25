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
#include <sys/time.h>

#include "utcp_priv.h"
#include "list.h"

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
        (r)->tv_sec--, (r)->tv_usec += USEC_PER_SEC;\
} while (0)
#endif

#ifdef max // it's a macro in mingw stdlib.h
#undef max
#endif
static inline size_t max(size_t a, size_t b) {
    return a > b ? a : b;
}

#ifdef min // it's a macro in mingw stdlib.h
#undef min
#endif
static inline size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

#ifdef UTCP_DEBUG
#include <stdarg.h>

static void debug(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

// write data to hex string
// @require assure available str buffer length >= 2 * data length
static uint32_t binTohex(char *str, uint32_t strglen, const void *vdata, uint32_t datalen) {
    char xchar;
    uint32_t pos = 0;
    const uint8_t *data = vdata;
    const uint8_t *dataend = data + datalen;
    while(data != dataend && pos < (strglen>>1)) {
        // convert upper 4 bit of current data pointer
        // for ASCI, offset values 0-9 by 48 and values 10-15 by 55
        xchar = *data >> 4;
        *str = xchar > 9? xchar + 55 : xchar + 48;
        ++str;
        // convert lower 4 bit of current data pointer
        xchar = *data & 0xf;
        *str = xchar > 9? xchar + 55 : xchar + 48;
        ++str;
        // advance to next data byte
        ++data;
        ++pos;
    }
    return pos;
}

static void print_packet(struct utcp *utcp, const char *dir, const void *pkt, size_t len) {
    struct hdr hdr;
    if(len < sizeof hdr) {
        debug("%p %s: short packet (" PRINT_SIZE_T " bytes)\n", utcp, dir, len);
        return;
    }

    memcpy(&hdr, pkt, sizeof hdr);
    fprintf (stderr, "%p %s: len=" PRINT_SIZE_T ", src=%u dst=%u seq=%u ack=%u trs=%u tra=%u wnd=%u ctl=",
        utcp, dir, len, hdr.src, hdr.dst, hdr.seq, hdr.ack, hdr.trs, hdr.tra, hdr.wnd);

    if(hdr.ctl & SYN)
        debug("SYN");
    if(hdr.ctl & RST)
        debug("RST");
    if(hdr.ctl & FIN)
        debug("FIN");
    if(hdr.ctl & ACK)
        debug("ACK");
    if(hdr.ctl & RTR)
        debug("RTR");

#ifdef UTCP_DEBUG_PACKETDATA
    if(len > sizeof hdr) {
        uint32_t datalen = len - sizeof hdr;
        const uint8_t *data = (const uint8_t*)pkt + sizeof hdr;
        uint32_t strglen = (datalen << 1) + 7;
        char *str = malloc(strglen + 1);
        if(!str) {
            debug("print_packet: out of memory");
            return;
        }
        memcpy(str, " data=", 6);

        binTohex(str + 6, strglen - 7, data, datalen);
        str[strglen-1] = 0;

        debug(str);
        free(str);
    }
#endif // UTCP_DEBUG_PACKETDATA

    debug("\n");
}
#else
#define debug(...)
#define print_packet(...)
#endif // UTCP_DEBUG

static void free_pkt_entry(struct pkt_entry_t *entry) {
    if(entry) {
        if(entry->pkt)
            free(entry->pkt);
        free(entry);
    }
}

static void start_connection_timer(struct utcp_connection *c) {
    gettimeofday(&c->conn_timeout, NULL);
    c->conn_timeout.tv_sec += c->utcp->timeout;
    debug("connection timeout set to %lu.%06lu\n", c->conn_timeout.tv_sec, c->conn_timeout.tv_usec);
}

static void stop_connection_timer(struct utcp_connection *c) {
    timerclear(&c->conn_timeout);
    debug("connection timeout cleared\n");
}

static void start_retransmit_timer_in(struct utcp_connection *c, uint32_t usec) {
    gettimeofday(&c->rtrx_timeout, NULL);
    c->rtrx_timeout.tv_usec += usec;
    while(c->rtrx_timeout.tv_usec >= USEC_PER_SEC) {
        c->rtrx_timeout.tv_usec -= USEC_PER_SEC;
        c->rtrx_timeout.tv_sec++;
    }
    debug("retransmit timeout set to %lu.%06lu (%u)\n", c->rtrx_timeout.tv_sec, c->rtrx_timeout.tv_usec, c->utcp->rto);
}

static void start_retransmit_timer(struct utcp_connection *c) {
    start_retransmit_timer_in(c, c->utcp->rto + c->rtrx_tolerance);
}

static void stop_retransmit_timer(struct utcp_connection *c) {
    timerclear(&c->rtrx_timeout);
    debug("retransmit timeout cleared\n");
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
        utcp->rto = utcp->srtt + max(4 * utcp->rttvar, CLOCK_GRANULARITY);
    }

    if(utcp->rto > MAX_RTO)
        utcp->rto = MAX_RTO;

    debug("rtt %u srtt %u rttvar %u rto %u\n", rtt, utcp->srtt, utcp->rttvar, utcp->rto);
}

static void set_state(struct utcp_connection *c, enum state state) {
    c->state = state;
    if(state == ESTABLISHED)
        stop_connection_timer(c);
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

// Store data into the buffer
ssize_t buffer_put_at(struct buffer *buf, size_t offset, const void *data, size_t len) {
    if(buf->maxsize <= buf->used)
        return 0;

    debug("buffer_put_at start:%lu used:%lu offset:%lu len:%lu size: %lu max:%lu\n", (unsigned long)buf->start, (unsigned long)buf->used, (unsigned long)offset, (unsigned long)len, (unsigned long)buf->size, (unsigned long)buf->maxsize);

    size_t required = offset + len;

    if(required > buf->maxsize) {
        if(offset >= buf->maxsize)
            return 0;
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
            } while(newsize < required);
        }
        if(newsize > buf->maxsize) {
            newsize = buf->maxsize;
        }
        char *newdata = realloc(buf->data, newsize);
        if(!newdata)
            return -1;
        buf->data = newdata;
        // if data wrapped around the ring, move the applicable parts to the end of the buffer
        if(buf->start + buf->used > buf->size) {
            size_t available = newsize - buf->size;
            size_t wrapped = buf->used - (buf->size - buf->start);
            size_t move_to_end = 0;
            size_t realign_to_begin = 0;
            if(wrapped > available) {
                move_to_end = available;
                realign_to_begin = wrapped - available;
            } else {
                move_to_end = wrapped;
                realign_to_begin = 0;
            }
            memmove(buf->data + buf->size, buf->data, move_to_end);
            memmove(buf->data, buf->data + move_to_end, realign_to_begin);
        }
        buf->size = newsize;
    }

    size_t append = 0;
    size_t append_offset = 0;
    size_t wrap = 0;
    size_t wrap_offset = 0;
    if(buf->start + offset <= buf->size) {
        append = buf->size - (buf->start + offset);
        append_offset = offset;
        wrap_offset = 0;
        if(append > len)
            append = len;
    } else {
        wrap_offset = offset - (buf->size - buf->start);
    }
    wrap = len - append;
    memcpy(buf->data + buf->start + append_offset, data, append);
    if(wrap) {
        memcpy(buf->data + wrap_offset, data + append, wrap);
    }
    if(required > buf->used)
        buf->used = required;
    return len;
}

ssize_t buffer_put(struct buffer *buf, const void *data, size_t len) {
    return buffer_put_at(buf, buf->used, data, len);
}

// Get data from the buffer. data can be NULL.
ssize_t buffer_get(struct buffer *buf, void *data, size_t len) {
    if(len > buf->used)
        len = buf->used;
    
    debug("buffer_get start:%lu used:%lu len:%lu size: %lu max:%lu\n", (unsigned long)buf->start, (unsigned long)buf->used, (unsigned long)len, (unsigned long)buf->size, (unsigned long)buf->maxsize);

    size_t at_end = buf->size - buf->start;
    if(data) {
        if(len >= at_end) {
            memcpy(data, buf->data + buf->start, at_end);
            memcpy(data + at_end, buf->data, len - at_end);
            buf->start = 0 + (len - at_end);
        } else {
            memcpy(data, buf->data + buf->start, len);
            buf->start += len;
        }
    } else {
        if(len >= at_end) {
            buf->start = 0 + (len - at_end);
        } else {
            buf->start += len;
        }
    }
    buf->used -= len;
    return len;
}

// Copy data from the buffer without removing it.
ssize_t buffer_copy(struct buffer *buf, void *data, size_t offset, size_t len) {
    if(offset >= buf->used)
        return 0;
    if(offset + len > buf->used)
        len = buf->used - offset;

    debug("buffer_copy start:%lu used:%lu offset:%lu len:%lu size: %lu max:%lu\n", (unsigned long)buf->start, (unsigned long)buf->used, (unsigned long)offset, (unsigned long)len, (unsigned long)buf->size, (unsigned long)buf->maxsize);

    size_t at_end = buf->size - buf->start;
    if(offset + len >= at_end) {
        if(offset <= at_end) {
            memcpy(data, buf->data + buf->start + offset, at_end - offset);
            memcpy(data + (at_end - offset), buf->data, len - (at_end - offset));
        } else {
            memcpy(data, buf->data + offset - at_end, len);
        }
    } else {
        memcpy(data, buf->data + buf->start + offset, len);
    }
    return len;
}

bool buffer_init(struct buffer *buf, uint32_t len, uint32_t maxlen) {
    memset(buf, 0, sizeof *buf);
    if(len) {
        buf->data = malloc(len);
        if(!buf->data)
            return false;
    }
    buf->size = len;
    buf->maxsize = maxlen;
    buf->start = 0;
    buf->used = 0;
    return true;
}

void buffer_exit(struct buffer *buf) {
    free(buf->data);
    memset(buf, 0, sizeof *buf);
}

uint32_t buffer_free(const struct buffer *buf) {
    return buf->maxsize - buf->used;
}

static void utcp_log_send_error(const struct pkt_t *pkt, size_t len, ssize_t sent, bool drop) {
    if(sent != len) {
        if(sent > len) {
            debug("Error: sent packet %u and ack %u but with a larger size than it should, %u of %u bytes sent", pkt->hdr.seq, pkt->hdr.ack, sent, len);
        }
        else if(sent >= 0) {
            // we do not handle split packets
            debug("Warning: failed to send packet %u and ack %u with only %u of %u bytes packet size sent, %s", pkt->hdr.seq, pkt->hdr.ack, sent, len, drop? "dropping the packet" : "retrying it later");
        }
        else if(sent == UTCP_WOULDBLOCK) {
            debug("Debug: failed to send packet %u and ack %u with UTCP_WOULDBLOCK, %s", pkt->hdr.seq, pkt->hdr.ack, drop? "dropping the packet" : "retrying it later");
        }
        else {
            // the pkt receiver might have gone offline causing the routing to fail
            // drop the packet and continue
            debug("Error: failed to send packet %u and ack %u with error %u, %s", pkt->hdr.seq, pkt->hdr.ack, sent, drop? "dropping the packet" : "retrying it later");
        }
    }
    else if(drop) {
        debug("Error: failed to send packet %u and ack %u, dropping the packet [sent=%u]", pkt->hdr.seq, pkt->hdr.ack, sent);
    }
}

static bool utcp_queue_packet(struct utcp_connection *c, struct pkt_t *pkt, size_t len) {
    struct pkt_entry_t *entry = malloc(sizeof *entry);
    if(!entry) {
        debug("Error: out of memory");
        return false;
    }

    entry->pkt = pkt;
    entry->len = len;
    list_insert_tail(c->pending_to_send, entry);

    return true;
}

static bool utcp_send_packet(struct utcp *utcp, const struct pkt_t *pkt, size_t len) {
    // attempt to immediately send the packet
    ssize_t sent = utcp->send(utcp, pkt, len);
    if(sent != len) {
        if(sent > len) {
            utcp_log_send_error(pkt, len, sent, false);
        }
        else if(sent >= 0 || sent == UTCP_WOULDBLOCK) {
            // when no data could be sent with possibly the header broken
            // or when the socket would block
            utcp_log_send_error(pkt, len, sent, true);
            return false;
        }
        else {
            // the pkt receiver might have gone offline causing the routing to fail
            // drop the packet and continue
            utcp_log_send_error(pkt, len, sent, true);
            return false;
        }
    }
    return true;
}

static bool utcp_send_packet_or_queue(struct utcp_connection *c, struct pkt_t *pkt, size_t len) {
    // when there are already packets queued, just append it to the list to be processed next utcp_timeout
    if(c->pending_to_send->count) {
        return utcp_queue_packet(c, pkt, len);
    }

    // attempt to immediately send the packet and queue if the socket send buffer is full
    struct utcp *utcp = c->utcp;
    ssize_t sent = utcp->send(utcp, pkt, len);
    if(sent != len) {
        if(sent > len) {
            utcp_log_send_error(pkt, len, sent, false);
        }
        else if(sent >= 0 || sent == UTCP_WOULDBLOCK) {
            // when no data could be sent with possibly the header broken
            // or when the socket would block, queue and retry later
            utcp_log_send_error(pkt, len, sent, false);
            return utcp_queue_packet(c, pkt, len);
        }
        else {
            // the pkt receiver might have gone offline causing the routing to fail
            // drop the packet and continue
            utcp_log_send_error(pkt, len, sent, true);
            return false;
        }
    }
    return true;
}

// returns whether all could be sent
static bool utcp_send_queued(struct utcp_connection *c) {
    struct utcp *utcp = c->utcp;
    for list_each(struct pkt_entry_t, entry, c->pending_to_send) {
        if(!entry || !entry->pkt) {
            list_delete_node(c->pending_to_send, node);
            continue;
        }

        ssize_t sent = utcp->send(utcp, entry->pkt, entry->len);
        if(sent != entry->len) {
            if(sent > entry->len) {
                utcp_log_send_error(entry->pkt, entry->len, sent, false);
            }
            else if(sent >= 0 || sent == UTCP_WOULDBLOCK) {
                // when no data could be sent with possibly the header broken
                // or when the socket would block, keep queued and retry later
                utcp_log_send_error(entry->pkt, entry->len, sent, false);
                return false;
            }
            else {
                // the pkt receiver might have gone offline causing the routing to fail
                // drop the packet and continue
                utcp_log_send_error(entry->pkt, entry->len, sent, true);
            }
        }

        list_delete_node(c->pending_to_send, node);
    }
    return true;
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

    if(c->pending_to_send)
        list_delete_list(c->pending_to_send);

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

    c->pending_to_send = list_alloc((list_action_t)free_pkt_entry);

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
    c->snd.ssthresh = 1 << 30;
    c->cwnd_max = 0;
    c->rtrx_tolerance = 0;
    c->utcp = utcp;

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
    c->priv = priv;

    struct pkt_t *pkt = calloc(1, sizeof(struct pkt_t));
    pkt->hdr.src = c->src;
    pkt->hdr.dst = c->dst;
    pkt->hdr.seq = c->snd.iss;
    pkt->hdr.wnd = c->rcv.wnd;
    pkt->hdr.ctl = SYN;

    set_state(c, SYN_SENT);

    print_packet(utcp, "send", pkt, sizeof pkt->hdr);
    if(!utcp_send_packet_or_queue(c, pkt, sizeof pkt->hdr)) {
        debug("Error: utcp_connect failed to send SYN");
        free(pkt);
        free_connection(c);
        return NULL;
    }

    start_connection_timer(c);

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
    c->rcv.wnd = c->rcvbuf.maxsize;
    set_state(c, ESTABLISHED);
}

static int ack(struct utcp_connection *c, bool sendatleastone) {
    if(sendatleastone) {
        c->sendatleastone = true;
    }

    // attempt to send packets from pending queue
    if(!utcp_send_queued(c)) {
        return UTCP_WOULDBLOCK;
    }

    int32_t left = seqdiff(c->snd.last, c->snd.nxt);
    assert(left >= 0);

    // limit by congestion window increased by utcp->mtu on each advance
    int32_t cwndleft = c->snd.cwnd - seqdiff(c->snd.nxt, c->snd.una);
    debug("cwndleft = %d (of %d)\n", cwndleft, c->snd.cwnd);

    if(cwndleft <= 0)
        cwndleft = 0;
    if(cwndleft < left)
        left = cwndleft;

    // If we don't need to send an ACK...
    if(!c->sendatleastone) {
        // then don't if we don't have any new data,
        if(!left)
            return 0;

        // and avoid sending small packets.
        if(left < c->utcp->mtu && seqdiff(c->snd.last, c->snd.una) >= c->utcp->mtu)
            return 0;
    }

    struct pkt_t *pkt;

    pkt = malloc(sizeof pkt->hdr + c->utcp->mtu);
    if(!pkt) {
        debug("Error: out of memory");
        return UTCP_ERROR;
    }

    pkt->hdr.src = c->src;
    pkt->hdr.dst = c->dst;
    pkt->hdr.ack = c->rcv.nxt;
    pkt->hdr.trs = c->snd.trs;
    pkt->hdr.tra = c->rcv.trs;
    pkt->hdr.wnd = c->rcv.wnd;
    pkt->hdr.ctl = c->rcv.ahead? ACK | RTR: ACK;
    pkt->hdr.aux = 0;

    int err = 0;
    do {
        uint32_t seglen = left > c->utcp->mtu ? c->utcp->mtu : left;
        uint32_t bufpos = seqdiff(c->snd.nxt, c->snd.una);
        pkt->hdr.seq = c->snd.nxt;

        left -= seglen;

        // adjust packet data length for the segment length
        // when FIN is not ack'ed yet len must be at least 1
        size_t datalen = seglen;
        if(seglen && fin_wanted(c, c->snd.nxt + seglen)) {
            datalen--;
            pkt->hdr.ctl |= FIN;
        }

        buffer_copy(&c->sndbuf, pkt->data, bufpos, datalen);

        size_t pktlen = sizeof pkt->hdr + datalen;
        print_packet(c->utcp, "send", pkt, pktlen);
        ssize_t sent = c->utcp->send(c->utcp, pkt, pktlen);
        if(sent != pktlen) {
            if(sent > pktlen) {
                utcp_log_send_error(pkt, pktlen, sent, false);
            }
            else if(sent >= 0 || sent == UTCP_WOULDBLOCK) {
                // when no data could be sent with possibly the header broken
                // or when the socket would block, don't advance but retry later
                utcp_log_send_error(pkt, pktlen, sent, false);
                err = UTCP_WOULDBLOCK;
                break;
            }
            else {
                // the pkt receiver might have gone offline causing the routing to fail
                // break loop and hope to recover some time later
                // it would only cause a retransmit when skipped
                utcp_log_send_error(pkt, pktlen, sent, false);
                err = UTCP_ERROR;
                break;
            }
        }

        // if anything sent, andvance
        c->snd.nxt += seglen;
        c->sendatleastone = false;

        // don't report back an ahead packet twice
        c->rcv.ahead = false;

        // on outgoing progess, initialize the timers if not already
        if(seglen > 0) {
            if(!timerisset(&c->rtrx_timeout))
                start_retransmit_timer(c);
            if(!timerisset(&c->conn_timeout))
                start_connection_timer(c);
        }

        // on successful send, start the RTT measurement if none already in progress
        if(!c->rtt_start.tv_sec) {
            gettimeofday(&c->rtt_start, NULL);
            c->rtt_seq = pkt->hdr.seq + seglen;
            debug("Starting RTT measurement, expecting ack %u\n", c->rtt_seq);
        }

    } while(left);

    free(pkt);
    return err;
}

ssize_t utcp_buffer(struct utcp_connection *c, const void *data, size_t len) {
    if(c->reapable) {
        debug("Error: utcp_buffer() called on closed connection %p\n", c);
        errno = EBADF;
        return UTCP_ERROR;
    }

    switch(c->state) {
    case CLOSED:
    case LISTEN:
    case SYN_SENT:
    case SYN_RECEIVED:
        debug("Error: utcp_buffer() called on unconnected connection %p\n", c);
        errno = ENOTCONN;
        return UTCP_ERROR;
    case ESTABLISHED:
    case CLOSE_WAIT:
        break;
    case FIN_WAIT_1:
    case FIN_WAIT_2:
    case CLOSING:
    case LAST_ACK:
    case TIME_WAIT:
        debug("Error: utcp_buffer() called on closing connection %p\n", c);
        errno = EPIPE;
        return UTCP_ERROR;
    }

    if(!len)
        return 0;

    if(!data) {
        errno = EFAULT;
        return UTCP_ERROR;
    }

    // attempt to add the new data to the send buffer
    ssize_t buffered = buffer_put(&c->sndbuf, data, len);
    if(buffered <= 0) {
        errno = EWOULDBLOCK;
        return UTCP_WOULDBLOCK;
    }

    // advance upper send buffer position to be sent
    c->snd.last += buffered;

    return buffered;
}

ssize_t utcp_send(struct utcp_connection *c, const void *data, size_t len) {
    // attempt to add the new data to the send buffer
    ssize_t buffered = utcp_buffer(c, data, len);

    // attempt to send the buffered data
    ack(c, false);

    return buffered;
}

static void swap_ports(struct hdr *hdr) {
    uint16_t tmp = hdr->src;
    hdr->src = hdr->dst;
    hdr->dst = tmp;
}

static bool send_meta(struct utcp_connection *c, uint32_t seq, uint32_t ack, uint16_t flags) {
    struct pkt_t *pkt;
    pkt = malloc(sizeof pkt->hdr + c->utcp->mtu);
    if(!pkt)
        return false;

    pkt->hdr.src = c->src;
    pkt->hdr.dst = c->dst;
    pkt->hdr.trs = c->snd.trs;
    pkt->hdr.tra = c->rcv.trs;
    pkt->hdr.wnd = c->rcv.wnd;
    pkt->hdr.aux = 0;
    pkt->hdr.seq = seq;
    pkt->hdr.ack = ack;
    pkt->hdr.ctl = flags;

    print_packet(c->utcp, "send_meta", pkt, sizeof pkt->hdr);
    if(!utcp_send_packet(c->utcp, pkt, sizeof pkt->hdr)) {
        debug("Error: send_meta failed to send %u", flags);
        free(pkt);
        return false;
    }
    free(pkt);
    return true;
}

static bool retransmit(struct utcp_connection *c) {
    if(c->state == CLOSED || c->snd.last == c->snd.una) {
        debug("Retransmit() called but nothing to retransmit!\n");
        stop_retransmit_timer(c);
        return true;
    }
    debug("retransmit() called\n.");

    struct utcp *utcp = c->utcp;

    // increment transmit number
    ++c->snd.trs;

    switch(c->state) {
        case SYN_SENT:
            // Send our SYN again
            if(!send_meta(c, c->snd.iss, 0, SYN)) {
                debug("Error: retransmit failed to send SYN");
                return false;
            }
            break;

        case SYN_RECEIVED:
            // Send SYNACK again
            if(!send_meta(c, c->snd.nxt, c->rcv.nxt, SYN | ACK)) {
                debug("Error: retransmit failed to send SYN | ACK");
                return false;
            }
            break;

        case ESTABLISHED:
        case FIN_WAIT_1:
        case CLOSE_WAIT:
        case CLOSING:
        case LAST_ACK:
            // reset seqno for the next packet to send
            c->snd.nxt = c->snd.una;

            // reduce congestion window and slow start threshold
            c->snd.ssthresh = max(c->snd.cwnd / 2, 2 * c->utcp->mtu);
            c->snd.cwnd = utcp->mtu;
            if( c->cwnd_max > 0 && c->snd.cwnd > c->cwnd_max )
                c->snd.cwnd = c->cwnd_max;
            break;

        case CLOSED:
        case LISTEN:
        case TIME_WAIT:
        case FIN_WAIT_2:
        default:
            // We shouldn't need to retransmit anything in this state.
            debug("Error: retransmit unexpected connection state %p %s\n", c, strstate[c->state]);
            stop_retransmit_timer(c);
            return false;
    }

    utcp->rto *= 2;
    if(utcp->rto > MAX_RTO)
        utcp->rto = MAX_RTO;
    c->rtt_start.tv_sec = 0; // invalidate RTT timer

    start_retransmit_timer(c);

    return true;
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
 * - the SACK entry is after ^, in that case just change the offset.
 * - the SACK entry starts before and ends after ^, so we have to
 *   change both its offset and size.
 * - the SACK entry is completely before ^, in that case delete it.
 */
static void sack_consume(struct utcp_connection *c, size_t len) {
    debug("sack_consume %lu\n", (unsigned long)len);

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
                // move remaining sacks one ahead
                memmove(&c->sacks[i], &c->sacks[i + 1], ((NSACKS - 1) - i) * sizeof c->sacks[i]);
                // clean last sack len
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

static size_t buffer_consumable(struct utcp_connection *c, size_t bufferOffset) {
    // Check if we can process out-of-order data now.
    if(c->sacks[0].len && bufferOffset >= c->sacks[0].offset) {
        // compute consumable end size
        size_t consumable = bufferOffset;
        for(int i = 0; i < NSACKS && c->sacks[i].len && c->sacks[i].offset <= consumable; i++)
            consumable = max(consumable, c->sacks[i].offset + c->sacks[i].len);
        return consumable - bufferOffset;
    }
    return 0;
}

static void handle_out_of_order(struct utcp_connection *c, uint32_t offset, const void *data, size_t len) {
    debug("out of order packet, offset %u\n", offset);

    // drop packets that are ahead of max buffer size
    if(offset >= c->rcvbuf.maxsize) {
        debug("warning: packet offset %u ahead of max buffer size %u\n", offset, c->rcvbuf.maxsize);
        return;
    }

    // Packet loss or reordering occurred. Store the data in the buffer.
    ssize_t rxd = buffer_put_at(&c->rcvbuf, offset, data, len);

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
                } else {
                    debug("SACK entries full, dropping packet\n");
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
    if(c->recv) {
        c->recv(c, data, len);
    }
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

    if(len < sizeof(struct hdr)) {
        errno = EBADMSG;
        return -1;
    }

    // Reinterpret potentially unaligned data to a pkt_t struct

    const struct pkt_t *pkt = data;
    len -= sizeof(struct hdr);

    // Drop packets with an unknown CTL flag

    if(pkt->hdr.ctl & ~(SYN | ACK | RTR | FIN | RST)) {
        errno = EBADMSG;
        return -1;
    }

    // Try to match the packet to an existing connection

    struct utcp_connection *c = find_connection(utcp, pkt->hdr.dst, pkt->hdr.src);

    // Is it for a new connection?

    if(!c) {
        // Ignore RST packets

        if(pkt->hdr.ctl & RST)
            return 0;

        // Is it a SYN packet?
        if(!(pkt->hdr.ctl & SYN) || (pkt->hdr.ctl & ACK)) {
            // No, we don't want your packets, send a RST back
            debug("Warning: connection rejected, hdr.ctl=%u\n", pkt->hdr.ctl);
            len = 1;
            goto reset;
        }

        // Are we LISTENing?
        if(!utcp->accept) {
            // No, we don't want your packets, send a RST back
            debug("Warning: connection rejected, not listening\n");
            len = 1;
            goto reset;
        }

        // If we don't want to accept it, send a RST back
        if((utcp->pre_accept && !utcp->pre_accept(utcp, pkt->hdr.dst))) {
            debug("Info: connection not accepted, dst=%u\n", (unsigned int)pkt->hdr.dst);
            len = 1;
            goto reset;
        }

        // Try to allocate memory, otherwise send a RST back
        c = allocate_connection(utcp, pkt->hdr.dst, pkt->hdr.src);
        if(!c) {
            debug("Error: failed to allocate connection\n");
            len = 1;
            goto reset;
        }

        // Return SYN+ACK, go to SYN_RECEIVED state
        c->snd.wnd = pkt->hdr.wnd;
        c->rcv.irs = pkt->hdr.seq;
        c->rcv.nxt = c->rcv.irs + 1;
        c->rcv.trs = pkt->hdr.trs;
        set_state(c, SYN_RECEIVED);

        struct pkt_t *response = calloc(1, sizeof(struct pkt_t));;
        response->hdr.dst = c->dst;
        response->hdr.src = c->src;
        response->hdr.ack = c->rcv.irs + 1;
        response->hdr.seq = c->snd.iss;
        response->hdr.trs = c->snd.trs;
        response->hdr.tra = c->rcv.trs;
        response->hdr.ctl = SYN | ACK;
        print_packet(c->utcp, "send", response, sizeof response->hdr);
        if(!utcp_send_packet_or_queue(c, response, sizeof response->hdr)) {
            debug("Error: utcp_recv failed to send SYN | ACK");
            free(response);
        }

        return 0;
    }

    debug("%p state %s\n", c->utcp, strstate[c->state]);

    // In case this is for a CLOSED connection, ignore the packet.
    // TODO: make it so incoming packets can never match a CLOSED connection.

    if(c->state == CLOSED) {
        debug("Got packet for closed connection\n");
        return 0;
    }

    // It is for an existing connection.

    // 1. Check packet validity

    // 1a. Drop packets with invalid flags or state

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
        debug("Error: utcp_recv unexpected connection state %p %s\n", c, strstate[c->state]);
        abort();
#endif
        break;
    }

    // 1b. Drop packets with invalid ACK sequence number
    // ackno should never be bigger than snd.last.
    // But it might be bigger than snd.nxt since we reset snd.nxt in retransmit and on triplicate ack.
    // And by package reordering it might be lower than snd.una, still it might have some useful data.

    if((pkt->hdr.ctl & ACK) && (seqdiff(pkt->hdr.ack, c->snd.last) > 0)) {
        debug("Packet ack seqno out of range: hdr.ack=%u snd.una=%u snd.nxt=%u snd.last=%u\n",
            pkt->hdr.ack, c->snd.una, c->snd.nxt, c->snd.last);
        // Ignore unacceptable RST packets.
        if(pkt->hdr.ctl & RST)
            return 0;
        goto reset;
    }

    // 2. Advance remote connectio state

    // 2a. Update received transmit number

    c->rcv.trs = pkt->hdr.trs;

    // 2b. Update send window

    c->snd.wnd = pkt->hdr.wnd;

    // 2c. Advance acknowledged progress
    // process acks even when hdr.seq doesn't match to adapt early and
    // get triplicate ack check work even when on both ends packets are not acceptable

    uint32_t prevrcvnxt = c->rcv.nxt;
    uint32_t advanced = 0;

    if(pkt->hdr.ctl & ACK)
    {
        int32_t progress = seqdiff(pkt->hdr.ack, c->snd.una);
        advanced = (progress > 0)? progress: 0;

        if(advanced) {
            // RTT measurement
            // check the measurement was started and the transmit number matches the last retransmit
            if(c->rtt_start.tv_sec && pkt->hdr.tra == c->snd.trs) {
                // check the acknowledged sequence number matches the sequence number of last RTT measurement sent
                if(c->rtt_seq == pkt->hdr.ack) {
                    struct timeval now, diff;
                    gettimeofday(&now, NULL);
                    timersub(&now, &c->rtt_start, &diff);
                    update_rtt(c, diff.tv_sec * USEC_PER_SEC + diff.tv_usec);
                    c->rtt_start.tv_sec = 0;
                } else if(c->rtt_seq < pkt->hdr.ack) {
                    debug("Cancelling RTT measurement: %u < %u\n", c->rtt_seq, pkt->hdr.ack);
                    c->rtt_start.tv_sec = 0;
                }
            }

            int32_t data_acked = advanced;

            // sub virtual SYN & FIN ack length
            switch(c->state) {
                case SYN_SENT:
                case SYN_RECEIVED:
                    data_acked--;
                    break;
                case FIN_WAIT_1:
                case CLOSING:
                case LAST_ACK:
                    // last ack is the FIN
                    if(pkt->hdr.ack == c->snd.last)
                        data_acked--;
                    break;
                default:
                    break;
            }

            assert(data_acked >= 0);

            int32_t bufused = seqdiff(c->snd.last, c->snd.una);
            assert(data_acked <= bufused);

            // Remove data from send buffer
            if(data_acked) {
                buffer_get(&c->sndbuf, NULL, data_acked);
            }

            // Advance snd.una & snd.nxt
            if(seqdiff(c->snd.nxt, pkt->hdr.ack) < 0)
                c->snd.nxt = pkt->hdr.ack;
            c->snd.una = pkt->hdr.ack;

            // Reset triplicate ack detection
            c->dupack = 0;

            // Update congestion window size
            // When the acknowledged transmit number matches the current transmit number, increase the congestion window.
            // Otherwise on retransmit keep it low to leave the receiver time to catch up if busy.
            if(pkt->hdr.tra == c->snd.trs) {
                if(c->snd.cwnd < c->snd.ssthresh) // slow start
                    c->snd.cwnd += min(data_acked, c->utcp->mtu);
                else // congestion avoidance
                    c->snd.cwnd += max(1, c->utcp->mtu * c->utcp->mtu / c->snd.cwnd);

                // Don't let the send window be larger than either our or the receiver's buffer.
                if(c->snd.cwnd > c->rcv.wnd)
                    c->snd.cwnd = c->rcv.wnd;
                if(c->snd.cwnd > c->sndbuf.maxsize)
                    c->snd.cwnd = c->sndbuf.maxsize;

                // limit to cwnd_max
                if(c->cwnd_max > 0 && c->snd.cwnd > c->cwnd_max)
                    c->snd.cwnd = c->cwnd_max;
            }

            // Check if we have sent a FIN that is now ACKed.
            switch(c->state) {
            case FIN_WAIT_1:
                if(c->snd.una == c->snd.last)
                    set_state(c, FIN_WAIT_2);
                break;
            case CLOSING:
                if(c->snd.una == c->snd.last)
                    set_state(c, TIME_WAIT);
                break;
            default:
                break;
            }

            // Call ack callback if set
            if(data_acked && c->ack)
                c->ack(c, data_acked);
        }
        else if(!progress && pkt->hdr.ctl & RTR) {
            // Count duplicate acks but disregard those for packets that were behind
            // Only for triplicate acks that signal missing data perform the retransmit
            c->dupack++;
            // ignore additional triplicate acks for old transmit sequences
            if(c->dupack == 3 && pkt->hdr.tra == c->snd.trs) {
                debug("Triplicate ACK\n");
                // Fast retransmit
                c->snd.nxt = c->snd.una;
                // Fast recovery
                c->snd.ssthresh = max(c->snd.cwnd / 2, 2 * c->utcp->mtu);
                c->snd.cwnd = c->snd.ssthresh;
                if(c->cwnd_max > 0 && c->snd.cwnd > c->cwnd_max)
                    c->snd.cwnd = c->cwnd_max;
            }
        }

        // Reset retransmit timer

        // reset on progress, so data can be continously sent over the channel
        // reset on empty response packets, to allow the sender to catch up on queued incoming unacceptable packets
        if(advanced || !len) {
            if(c->snd.una == c->snd.last)
                stop_retransmit_timer(c);
            else
                start_retransmit_timer(c);
        }
    }

    // 3. Check for acceptable incoming data

    // 3a. Check packet acceptance

    int32_t rcv_offset = 0;
    size_t data_offset = 0;
    size_t data_len = len;
    bool acceptable = false;

    if(c->state == SYN_SENT)
        acceptable = true;
    else {
        rcv_offset = seqdiff(pkt->hdr.seq, c->rcv.nxt);
        c->rcv.ahead = rcv_offset > 0;

        // always accept control data packets that are ahead
        if(!len)
            acceptable = rcv_offset >= 0;
        else {
            // accept all packets in sequence
            if(rcv_offset == 0)
                acceptable = true;
            // accept overlapping packets
            else if(rcv_offset < 0) {
                // cut already accepted front overlapping
                // but even accept packets of len 0 to process valuable flag info
                // like the FIN without requiring a retransmit
                if(len >= -rcv_offset) {
                    data_offset = -rcv_offset;
                    data_len -= data_offset;
                    acceptable = true;
                }
            } else {
                // accept packets that can partially be stored to the buffer
                acceptable = rcv_offset < c->rcvbuf.maxsize;
            }
        }
    }

    // 3b. Reset connection timer
    // whenever we advance or get an acceptable packet, deem the connection active

    if(advanced || acceptable) {
        if(c->snd.una != c->snd.last)
            start_connection_timer(c);
        else {
            switch(c->state) {
            case FIN_WAIT_1:
            case FIN_WAIT_2:
            case CLOSING:
            case LAST_ACK:
            case TIME_WAIT:
                start_connection_timer(c);
                break;
            default:
                // disable connection timer till next packet is sent
                stop_connection_timer(c);
                break;
            }
        }
    }

    // 3c. Drop unacceptable packets
    // seqno rolls back on retransmit, so possibly a previous ack got dropped

    if(!acceptable) {
        debug("Packet not acceptable, %u <= %u + " PRINT_SIZE_T " < %u\n", c->rcv.nxt, pkt->hdr.seq, len, c->rcv.nxt + c->rcvbuf.maxsize);
        // Ignore unacceptable RST packets.
        if(pkt->hdr.ctl & RST)
            return 0;
        // Otherwise, send an ACK back in the hope things improve.
        // needed to trigger the triple ack and reset the sender's seqno
        ack(c, true);
        return 0;
    }

    // 4. Process state changes

    // 4a. RST state changes

    if(pkt->hdr.ctl & RST) {
        switch(c->state) {
        case SYN_SENT:
            if(!(pkt->hdr.ctl & ACK))
                return 0;
            // The peer has refused our connection.
            debug("Warning: peer refused connection, %p state=%s\n", c, strstate[c->state]);
            set_state(c, CLOSED);
            errno = ECONNREFUSED;
            if(c->recv)
                c->recv(c, NULL, 0);
            return 0;
        case SYN_RECEIVED:
            if(pkt->hdr.ctl & ACK)
                return 0;
            // We haven't told the application about this connection yet. Silently delete.
            free_connection(c);
            return 0;
        case ESTABLISHED:
        case FIN_WAIT_1:
        case FIN_WAIT_2:
        case CLOSE_WAIT:
            if(pkt->hdr.ctl & ACK)
                return 0;
            // The peer has aborted our connection.
            debug("Info: connection aborted, %p state=%s\n", c, strstate[c->state]);
            set_state(c, CLOSED);
            errno = ECONNRESET;
            if(c->recv)
                c->recv(c, NULL, 0);
            return 0;
        case CLOSING:
        case LAST_ACK:
        case TIME_WAIT:
            if(pkt->hdr.ctl & ACK)
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
            debug("Warning: utcp_recv RST unexpected connection state %p %s\n", c, strstate[c->state]);
            break;
        }
    }

    // 4b. SYN state changes

    if(pkt->hdr.ctl & SYN) {
        switch(c->state) {
        case SYN_SENT:
            // This is a SYNACK. It should always have ACKed the SYN.
            if(!advanced) {
                debug("Warning: SYNACK didn't advance, %p state=%s\n", c, strstate[c->state]);
                goto reset;
            }
            c->rcv.irs = pkt->hdr.seq;
            c->rcv.nxt = pkt->hdr.seq;
            c->rcv.wnd = c->rcvbuf.maxsize;
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
            debug("Warning: received a second SYN, %p state=%s\n", c, strstate[c->state]);
            goto reset;
        default:
            debug("Warning: utcp_recv SYN unexpected connection state %p %s\n", c, strstate[c->state]);
            return 0;
        }

        // SYN counts as one sequence number
        c->rcv.nxt++;
    }

    // 4c. new data state changes

    if(c->state == SYN_RECEIVED) {
        // This is the ACK after the SYNACK. It should always have ACKed the SYNACK.
        if(!advanced) {
            debug("Warning: ACK didn't advance the SYNACK, %p state=%s\n", c, strstate[c->state]);
            goto reset;
        }

        // Are we still LISTENing?
        if(!utcp->accept) {
            debug("Warning: not listening, closing %p state=%s\n", c, strstate[c->state]);
            set_state(c, CLOSED);
            c->reapable = true;
            goto reset;
        }
        
        utcp->accept(c, c->src);
        if(c->state != ESTABLISHED) {
            debug("Warning: couldn't establish connection, closing %p state=%s\n", c, strstate[c->state]);
            set_state(c, CLOSED);
            c->reapable = true;
            goto reset;
        }
    }

    bool handle_incoming = false;
    if(data_len) {
        switch(c->state) {
        case SYN_SENT:
        case SYN_RECEIVED:
            // This should never happen.
            debug("Warning: utcp_recv handle_incoming_data unexpected connection state %p %s\n", c, strstate[c->state]);
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
            debug("Warning: received data after the FIN, %p state=%s\n", c, strstate[c->state]);
            goto reset;
        default:
            debug("Warning: utcp_recv handle_incoming_data unexpected connection state %p %s\n", c, strstate[c->state]);
            return 0;
        }

        // delay to process the new data received till after the ack
        // for quicker response time and a decreased rtt measurement variance
        handle_incoming = true;
    }

    // 4d. FIN state changes

    bool closed = false;
    if((pkt->hdr.ctl & FIN) && pkt->hdr.seq + len == c->rcv.nxt) {
        switch(c->state) {
        case SYN_SENT:
        case SYN_RECEIVED:
            // This should never happen.
            debug("Warning: utcp_recv FIN unexpected connection state %p %s\n", c, strstate[c->state]);
            break;
        case ESTABLISHED:
            set_state(c, CLOSE_WAIT);
            break;
        case FIN_WAIT_1:
            set_state(c, CLOSING);
            break;
        case FIN_WAIT_2:
            set_state(c, TIME_WAIT);
            break;
        case CLOSE_WAIT:
        case CLOSING:
        case LAST_ACK:
        case TIME_WAIT:
            // Ehm, no. We should never receive a second FIN.
            debug("Warning: received a second FIN, %p state=%s\n", c, strstate[c->state]);
            goto reset;
        default:
            debug("Warning: utcp_recv FIN unexpected connection state %p %s\n", c, strstate[c->state]);
            break;
        }

        // FIN counts as one sequence number
        c->rcv.nxt++;
        len++;

        closed = true;
    }

    // 5. Consume incoming packet data, advancing the rcv.nxt counter
    char* frombuf = NULL;
    if(handle_incoming && rcv_offset <= 0)
    {
        size_t consumable = buffer_consumable(c, data_len);
        if( consumable )
        {
            debug("consuming buffered SACKs up to %u\n", (unsigned long)( pkt->hdr.seq + data_offset + data_len + consumable));

            frombuf = malloc(data_len + consumable);
            memcpy( frombuf, pkt->data + data_offset, data_len );
            buffer_copy(&c->rcvbuf, frombuf + data_len, data_len, consumable);
            data_len += consumable;
        }

        if(c->rcvbuf.used)
            sack_consume(c, data_len);

        // advance ack sequence number for the next packet to receive
        c->rcv.nxt += data_len;
    }

    // 6. Ack accepted packets

    // Now we send something back if:
    // - we received data to process
    //   -> sendatleastone = true, with RTR flag set for the Triplicate ACK if ahead
    // - rcv.nxt is changed (ie, we got a SYNACK)
    //   -> sendatleastone = true
    // - or we got an ack, so we should maybe send a bit more data
    //   -> sendatleastone = false
    ack(c, len || prevrcvnxt != c->rcv.nxt);

    // 7. Send new data to application
    // Given the ack is used for roundtrip measurement and a too high response time or variation
    // easily implicts retransmits, delay all compution intensive processing till after the ack.

    // Handle new incoming data.
    if(handle_incoming)
    {
        if(rcv_offset > 0)
        {
            handle_out_of_order(c, rcv_offset, pkt->data, data_len);
        }
        else
        {
            const char* rcv_data = frombuf ? frombuf : pkt->data + data_offset;
            handle_in_order(c, rcv_data, data_len);
        }
    }

    if( frombuf ) {
        free(frombuf);
    }

    // Inform the application when the peer closed the connection.
    if(closed && c->recv) {
        errno = 0;
        c->recv(c, NULL, 0);
    }

    return 0;

reset:
    {
        struct pkt_t *response = malloc(sizeof(struct pkt_t));
        memcpy(&response->hdr, &pkt->hdr, sizeof pkt->hdr);

        swap_ports(&response->hdr);
        response->hdr.trs = c? c->snd.trs: 0;
        response->hdr.tra = pkt->hdr.trs;
        response->hdr.wnd = 0;
        if(response->hdr.ctl & ACK) {
            response->hdr.seq = response->hdr.ack;
            response->hdr.ctl = RST;
        } else {
            response->hdr.ack = response->hdr.seq + len;
            response->hdr.seq = 0;
            response->hdr.ctl = RST | ACK;
        }
        print_packet(utcp, "send", response, sizeof response->hdr);

        // attempt to report back the RST but wait for the next failed packet when not in a condition to send
        if(!utcp_send_packet(utcp, response, sizeof response->hdr)) {
            debug("Info: utcp_recv failed to send back RST");
            free(response);
        }
        return 0;
    }
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

    // inc .last for the FIN
    c->snd.last++;

    ack(c, false);
    return 0;
}

int utcp_close(struct utcp_connection *c) {
    if(utcp_shutdown(c, SHUT_RDWR) && errno != ENOTCONN)
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

    struct pkt_t *pkt = calloc(1, sizeof(struct pkt_t));
    pkt->hdr.src = c->src;
    pkt->hdr.dst = c->dst;
    pkt->hdr.seq = c->snd.nxt;
    pkt->hdr.trs = c->snd.trs;
    pkt->hdr.tra = c->rcv.trs;
    pkt->hdr.ctl = RST;

    print_packet(c->utcp, "send", pkt, sizeof pkt->hdr);
    if(!utcp_send_packet_or_queue(c, pkt, sizeof pkt->hdr)) {
        debug("Error: utcp_abort failed to send RST");
        free(pkt);
    }
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
    struct timeval next = {3600, 0};

    static int next_conn = 0;

    for(int i = 0; i < utcp->nconnections; ++i, ++next_conn) {
        next_conn %= utcp->nconnections;
        
        struct utcp_connection *c = utcp->connections[next_conn];
        if(!c)
            continue;

        // delete connections that have been utcp_close()d.
        if(c->state == CLOSED) {
            if(c->reapable) {
                debug("Reaping %p\n", c);
                free_connection(c);
                --i;
                --next_conn;
            }
            continue;
        }

        // check connection timeout
        if(timerisset(&c->conn_timeout)) {
             if(timercmp(&c->conn_timeout, &now, <)) {
                errno = ETIMEDOUT;
                c->state = CLOSED;
                if(c->recv)
                    c->recv(c, NULL, 0);
                continue;
            }
            struct timeval diff;
            timersub(&c->conn_timeout, &now, &diff);
            if(timercmp(&diff, &next, <))
                next = diff;
        }

        // attempt to send packets from pending queue
        if(!utcp_send_queued(c)) {
            // retry with 1ms timeout
            struct timeval retry = {0,1000};
            if(timercmp(&retry, &next, <))
                next = retry;

            // break on UTCP_WOULDBLOCK to proceed with the next connection next time
            break;
        }

        // when there's nothing pending queued, check the retransmit timeout
        if(timerisset(&c->rtrx_timeout)) {
            if(timercmp(&c->rtrx_timeout, &now, <)) {
                debug("retransmit()\n");
                if(!retransmit(c)) {
                    // when the retransmit failed, retry with 1ms timeout
                    struct timeval retry = {0,1000};
                    if(timercmp(&retry, &next, <))
                        next = retry;
                    continue;
                }
            }
            struct timeval diff;
            timersub(&c->rtrx_timeout, &now, &diff);
            if(timercmp(&diff, &next, <))
                next = diff;
        }

        // when the connection is established, process all data to be sent
        if(c->state == ESTABLISHED || c->state == CLOSE_WAIT) {
            // when the poll callback is set and there's free buffer left, poll new data to the buffer
            if(buffer_free(&c->sndbuf) && c->poll) {
                c->poll(c, buffer_free(&c->sndbuf));
            }

            // try to send any remainining buffered data
            // the polling might only call utcp_send and ack when there's something new to send
            // on error return with a 1ms timeout to retry soon
            int err = ack(c, false);
            if(0 != err) {
                struct timeval retry = {0,1000};
                if(timercmp(&retry, &next, <))
                    next = retry;

                // break on UTCP_WOULDBLOCK to proceed with the next connection next time
                if(UTCP_WOULDBLOCK == err)
                    break;
            }
        }
        // also retry the last shutdown send if failed
        else if(c->state == FIN_WAIT_1 || c->state == CLOSING) {
            // on error return with a 1ms timeout to retry soon
            int err = ack(c, false);
            if(0 != err) {
                struct timeval retry = {0,1000};
                if(timercmp(&retry, &next, <))
                    next = retry;

                // break on UTCP_WOULDBLOCK to proceed with the next connection next time
                if(UTCP_WOULDBLOCK == err)
                    break;
            }
        }
    }

    return next;
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
    utcp->timeout = DEFAULT_USER_TIMEOUT; // sec
    utcp->rto = START_RTO; // usec

    return utcp;
}

void utcp_exit(struct utcp *utcp) {
    if(!utcp)
        return;
    for(int i = 0; i < utcp->nconnections; i++) {
        struct utcp_connection *c = utcp->connections[i];
        if(!c->reapable)
            debug("Warning, freeing unclosed connection %p\n", utcp->connections[i]);
        if(c->pending_to_send)
            list_delete_list(c->pending_to_send);
        buffer_exit(&c->rcvbuf);
        buffer_exit(&c->sndbuf);
        free(c);
    }
    free(utcp->connections);
    free(utcp);
}

uint16_t utcp_get_mtu(struct utcp *utcp) {
    return utcp ? utcp->mtu : 0;
}

void utcp_set_mtu(struct utcp *utcp, uint16_t mtu) {
    // directly set the mtu so utcp_get_mtu matches the value specified
    if(utcp)
        utcp->mtu = mtu;
}

uint16_t utcp_update_mtu(struct utcp *utcp, uint16_t mtu) {
    if(utcp)
    {
        // handle overhead of the header
        utcp->mtu = mtu > sizeof(struct hdr)? mtu - sizeof(struct hdr): DEFAULT_MTU;
        return utcp->mtu;
    }
    return 0;
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
    if(size < c->utcp->mtu)
        size = c->utcp->mtu;
    if(size >= 1U << 30)
        size = 1U << 30;
    c->rcvbuf.maxsize = size;
    if(c->state == ESTABLISHED)
        c->rcv.wnd = size;
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

void utcp_set_ack_cb(struct utcp_connection *c, utcp_ack_t ack) {
    if(c)
        c->ack = ack;
}

void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_pre_accept_t pre_accept) {
    if(utcp) {
        utcp->accept = accept;
        utcp->pre_accept = pre_accept;
    }
}

bool utcp_set_cwnd_max(struct utcp_connection *connection, uint32_t max) {
    if(!connection || (max != 0 && max < connection->utcp->mtu)) {
        return false;
    }
    connection->cwnd_max = max;
    return true;
}

bool utcp_get_cwnd_max(struct utcp_connection *connection, uint32_t *max) {
    if(connection) {
        *max = connection->cwnd_max;
        return true;
    }
    *max = 0;
    return false;
}

bool utcp_set_rtrx_tolerance(struct utcp_connection *connection, uint32_t tolerance) {
    if(!connection) {
        return false;
    }
    connection->rtrx_tolerance = tolerance;
    return true;
}

bool utcp_get_rtrx_tolerance(struct utcp_connection *connection, uint32_t *tolerance) {
    if(connection) {
        *tolerance = connection->rtrx_tolerance;
        return true;
    }
    *tolerance = 0;
    return false;
}
