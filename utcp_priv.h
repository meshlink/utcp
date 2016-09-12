/*
    utcp.h -- Userspace TCP
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

#ifndef UTCP_PRIV_H
#define UTCP_PRIV_H

#define UTCP_INTERNAL
#include "utcp.h"

#define PREP(l) char pkt[(l) + sizeof struct hdr]; struct hdr *hdr = &pkt;

#define SYN 1
#define ACK 2
#define FIN 4
#define RST 8

#define NSACKS 4
#define DEFAULT_SNDBUFSIZE 4096
#define DEFAULT_MAXSNDBUFSIZE 131072
#define DEFAULT_RCVBUFSIZE 0
#define DEFAULT_MAXRCVBUFSIZE 131072

#define DEFAULT_MTU 1000

#define USEC_PER_SEC 1000000
#define DEFAULT_USER_TIMEOUT 60 // sec
#define CLOCK_GRANULARITY 1000 // usec
#define START_RTO 1000000 // usec
#define MAX_RTO  60000000 // usec

struct hdr {
    uint16_t src; // Source port
    uint16_t dst; // Destination port
    uint32_t seq; // Sequence number
    uint32_t ack; // Acknowledgement number
    uint32_t wnd; // Window size
    uint16_t ctl; // Flags (SYN, ACK, FIN, RST)
    uint16_t aux; // other stuff
};

struct pkt_t {
    struct hdr      hdr;
    char            data[];
};

struct pkt_entry_t {
    struct pkt_t    *pkt;
    uint32_t        len;
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

static const char *strstate[] __attribute__((unused)) = {
    [CLOSED] = "CLOSED",
    [LISTEN] = "LISTEN",
    [SYN_SENT] = "SYN_SENT",
    [SYN_RECEIVED] = "SYN_RECEIVED",
    [ESTABLISHED] = "ESTABLISHED",
    [FIN_WAIT_1] = "FIN_WAIT_1",
    [FIN_WAIT_2] = "FIN_WAIT_2",
    [CLOSE_WAIT] = "CLOSE_WAIT",
    [CLOSING] = "CLOSING",
    [LAST_ACK] = "LAST_ACK",
    [TIME_WAIT] = "TIME_WAIT"
};

struct buffer {
    char *data; // is implemented as a ring buffer so use buffer_copy to get data before passing to application
    uint32_t start;
    uint32_t used;
    uint32_t size;
    uint32_t maxsize;
};

extern uint32_t buffer_free(const struct buffer *buf);
extern ssize_t buffer_put_at(struct buffer *buf, size_t offset, const void *data, size_t len);
extern ssize_t buffer_put(struct buffer *buf, const void *data, size_t len);
extern ssize_t buffer_get(struct buffer *buf, void *data, size_t len);
extern ssize_t buffer_copy(struct buffer *buf, void *data, size_t offset, size_t len);
extern bool buffer_init(struct buffer *buf, uint32_t len, uint32_t maxlen);
extern void buffer_exit(struct buffer *buf);

struct sack {
    uint32_t offset;
    uint32_t len;
};

struct utcp_connection {
    void *priv;
    struct utcp *utcp;

    bool reapable;

    // Callbacks

    utcp_recv_t recv;
    utcp_poll_t poll;
        utcp_ack_t ack;

    // TCP State

    uint16_t src;
    uint16_t dst;
    enum state state;

    struct {
        uint32_t una;
        uint32_t nxt;
        uint32_t wnd;
        uint32_t iss;

        uint32_t last;
        uint32_t cwnd;
        uint32_t ssthresh;
    } snd;

    struct {
        uint32_t nxt;
        uint32_t wnd;
        uint32_t irs;
    } rcv;

    int dupack;

    // Timers

    struct timeval conn_timeout;
    struct timeval rtrx_timeout;
    struct timeval rtt_start;
    uint32_t rtrx_tolerance; // usec
    uint32_t rtt_seq;

    // Buffers

    struct buffer sndbuf;
    struct buffer rcvbuf;
    struct sack sacks[NSACKS];
    struct list_t *pending_to_send;
    bool sendatleastone;

    // Per-socket options

    bool nodelay;
    bool keepalive;
    uint32_t cwnd_max;

    // Congestion avoidance state

    struct timeval tlast;
    uint64_t bandwidth;
};

struct utcp {
    void *priv;

    // Callbacks

    utcp_accept_t accept;
    utcp_pre_accept_t pre_accept;
    utcp_send_t send;

    // Global socket options

    uint16_t mtu;
    int timeout; // sec

    // RTT variables

    uint32_t srtt; // usec
    uint32_t rttvar; // usec
    uint32_t rto; // usec

    // Connection management

    struct utcp_connection **connections;
    int nconnections;
    int nallocated;
};

#endif
