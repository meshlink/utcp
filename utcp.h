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

#ifndef UTCP_H
#define UTCP_H

#include <stdint.h>
#include <stdbool.h>

#include "compat.h"

#ifndef UTCP_INTERNAL
struct utcp {
	void *priv;
};

struct utcp_connection {
	void *priv;
	struct utcp *utcp;
};
#else
struct utcp;
struct utcp_connection;
#endif

#define UTCP_SHUT_RD 0
#define UTCP_SHUT_WR 1
#define UTCP_SHUT_RDWR 2

// for the send callback
#define UTCP_ERROR -1
#define UTCP_WOULDBLOCK -2

typedef bool (*utcp_pre_accept_t)(struct utcp *utcp, uint16_t port);
typedef void (*utcp_accept_t)(struct utcp_connection *utcp_connection, uint16_t port);

typedef ssize_t (*utcp_send_t)(struct utcp *utcp, const void *data, size_t len);
typedef void (*utcp_recv_t)(struct utcp_connection *connection, const void *data, size_t len);

typedef void (*utcp_ack_t)(struct utcp_connection *connection, size_t len);
typedef int (*utcp_poll_t)(struct utcp_connection *connection, size_t len);

extern struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv);
extern void utcp_exit(struct utcp *utcp);

extern struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t port, utcp_recv_t recv, void *priv);
extern void utcp_accept(struct utcp_connection *utcp, utcp_recv_t recv, void *priv);
extern ssize_t utcp_buffer(struct utcp_connection *connection, const void *data, size_t len);
extern ssize_t utcp_send(struct utcp_connection *connection, const void *data, size_t len);
extern ssize_t utcp_recv(struct utcp *utcp, const void *data, size_t len);
extern int utcp_close(struct utcp_connection *connection);
extern int utcp_abort(struct utcp_connection *connection);
extern int utcp_shutdown(struct utcp_connection *connection, int how);
extern struct timeval utcp_timeout(struct utcp *utcp);
extern void utcp_set_recv_cb(struct utcp_connection *connection, utcp_recv_t recv);
extern void utcp_set_poll_cb(struct utcp_connection *connection, utcp_poll_t poll);
extern void utcp_set_ack_cb(struct utcp_connection *connection, utcp_ack_t ack);
extern void utcp_set_accept_cb(struct utcp *utcp, utcp_accept_t accept, utcp_pre_accept_t pre_accept);
extern bool utcp_is_active(struct utcp *utcp);

// Global socket options

extern int utcp_get_user_timeout(struct utcp *utcp);
extern void utcp_set_user_timeout(struct utcp *utcp, int seconds);

extern uint16_t utcp_get_mtu(struct utcp *utcp);
// Set mtu to exactly the given value
extern void utcp_set_mtu(struct utcp *utcp, uint16_t mtu);
// Set the mtu to the given value, minus the size of the utcp header. Returns the effective remaining mtu.
extern uint16_t utcp_update_mtu(struct utcp *utcp, uint16_t mtu);

// Per-socket options

extern size_t utcp_get_sndbuf(struct utcp_connection *connection);
extern void utcp_set_sndbuf(struct utcp_connection *connection, size_t size);
extern size_t utcp_get_sndbuf_free(struct utcp_connection *connection);

extern size_t utcp_get_rcvbuf(struct utcp_connection *connection);
extern void utcp_set_rcvbuf(struct utcp_connection *connection, size_t size);
extern size_t utcp_get_rcvbuf_free(struct utcp_connection *connection);

extern bool utcp_get_nodelay(struct utcp_connection *connection);
extern void utcp_set_nodelay(struct utcp_connection *connection, bool nodelay);

extern bool utcp_get_keepalive(struct utcp_connection *connection);
extern void utcp_set_keepalive(struct utcp_connection *connection, bool keepalive);

extern size_t utcp_get_outq(struct utcp_connection *connection);

/** Set connection maximum congestion window size.
 * Set to 0 for no maximum.
 * Must be at least as large as mtu.
 * Returns true if limit was set successfully, false otherwise.
 */
extern bool utcp_set_cwnd_max(struct utcp_connection *conection, uint32_t max);

/** Get connection maximum congestion window size.
 * Returns true on success, false on error.
 * Sets `max` to current limit, or 0 if no limit is set.
 */
extern bool utcp_get_cwnd_max(struct utcp_connection *connection, uint32_t *max);

/** Set additional connection retransmit tolerance in usec to adapt for bad connections.
 * Returns true on success, false on error.
 */
extern bool utcp_set_rtrx_tolerance(struct utcp_connection *conection, uint32_t tolerance);

/** Get additional connection retransmit tolerance in usec.
 * Returns true on success, false on error.
 * Sets `tolerance` to retransmit tolerance, or 0 if no value is set.
 */
extern bool utcp_get_rtrx_tolerance(struct utcp_connection *connection, uint32_t *tolerance);

#endif
