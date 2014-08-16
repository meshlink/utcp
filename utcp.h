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

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

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

typedef bool (*utcp_pre_accept_t)(struct utcp *utcp, uint16_t port);
typedef void (*utcp_accept_t)(struct utcp_connection *utcp_connection, uint16_t port);

typedef int (*utcp_send_t)(struct utcp *utcp, const void *data, size_t len);
typedef int (*utcp_recv_t)(struct utcp_connection *connection, const void *data, size_t len);

extern struct utcp *utcp_init(utcp_accept_t accept, utcp_pre_accept_t pre_accept, utcp_send_t send, void *priv);
extern void utcp_exit(struct utcp *utcp);

extern void utcp_set_mtu(struct utcp *utcp, uint16_t mtu);

extern struct utcp_connection *utcp_connect(struct utcp *utcp, uint16_t port, utcp_recv_t recv, void *priv);
extern void utcp_accept(struct utcp_connection *utcp, utcp_recv_t recv, void *priv);
extern ssize_t utcp_send(struct utcp_connection *connection, const void *data, size_t len);
extern int utcp_recv(struct utcp *utcp, const void *data, size_t len);
extern int utcp_close(struct utcp_connection *connection);
extern int utcp_abort(struct utcp_connection *connection);
extern int utcp_shutdown(struct utcp_connection *connection, int how);
extern int utcp_timeout(struct utcp *utcp);
extern int utcp_set_connection_timeout(struct utcp *utcp, int seconds);

#endif
