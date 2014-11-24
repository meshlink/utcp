#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <glib.h>

#include "utcp.h"


// short-circuit send (call peer's recv directly)
ssize_t do_send(struct utcp *utcp, const void *data, size_t len) {
	static int count = 0;
	g_assert(++count <= 1000);  // catch packet storms
	return utcp_recv(utcp->priv /* peer */, data, len);
}




void t_init_nullsend(void) {
	g_assert_null(utcp_init(NULL, NULL, NULL, NULL));
}


bool t_connect_nullaccept_cbflag;
ssize_t t_connect_nullaccept_recv_cb(struct utcp_connection *c, const void *data, size_t len) {
	t_connect_nullaccept_cbflag = true;
	g_assert_null(data);
	g_assert_cmpuint(len, ==, 0);
	return len;
}
void t_connect_nullaccept(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_nullaccept_cbflag = false;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(NULL, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_false(t_connect_nullaccept_cbflag);
	c = utcp_connect(a, 123, t_connect_nullaccept_recv_cb, NULL);
	g_assert_nonnull(c);
	g_assert_true(t_connect_nullaccept_cbflag);

	utcp_exit(a);
	utcp_exit(b);
}


int t_connect_nullpreaccept_cbflags;
void t_connect_nullpreaccept_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_connect_nullpreaccept_cbflags |= 1;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	// no call to utcp_accept() -> reset
}
ssize_t t_connect_nullpreaccept_recv_cb(struct utcp_connection *c, const void *data, size_t len) {
	t_connect_nullpreaccept_cbflags |= 2;
	g_assert_null(data);
	g_assert_cmpuint(len, ==, 0);
	return len;
}
void t_connect_nullpreaccept(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_nullpreaccept_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_connect_nullpreaccept_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_connect_nullpreaccept_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_connect_nullpreaccept_recv_cb, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_connect_nullpreaccept_cbflags, ==, 0x3);	// accept and recv called

	utcp_exit(a);
	utcp_exit(b);
}


int t_connect_closed_cbflags;
bool t_connect_closed_preaccept_cb(struct utcp *utcp, uint16_t port) {
	t_connect_closed_cbflags |= 1;
	g_assert_nonnull(utcp);
	g_assert_cmpuint(port, ==, 123);
	return false;
}
void t_connect_closed_accept_cb(struct utcp_connection *c, uint16_t port) {
	g_assert_not_reached();
}
ssize_t t_connect_closed_recv_cb(struct utcp_connection *c, const void *data, size_t len) {
	t_connect_closed_cbflags |= 2;
	g_assert_null(data);
	g_assert_cmpuint(len, ==, 0);
	return len;
}
void t_connect_closed(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_closed_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_connect_closed_accept_cb, t_connect_closed_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_connect_closed_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_connect_closed_recv_cb, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_connect_closed_cbflags, ==, 0x3);	// preaccept and recv called

	utcp_exit(a);
	utcp_exit(b);
}


int t_connect_open_cbflags;
ssize_t t_connect_open_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_connect_open_cbflags |= 1;
	return len;
}
ssize_t t_connect_open_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	g_assert_not_reached();
}
void t_connect_open_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_connect_open_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_connect_open_recv_cb_b, NULL);
}
void t_connect_open(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_open_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_connect_open_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_connect_open_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_connect_open_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_connect_open_cbflags, ==, 0x2); // accept called

	// connection should be established
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);
	g_assert_cmphex(t_connect_open_cbflags, ==, 0x3); // accept and recv_b called

	g_assert_cmpint(utcp_close(c), ==, 0);
	utcp_exit(a);
	utcp_exit(b);
}


bool t_connect_nullrecv_cbflag;
void t_connect_nullrecv_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_connect_nullrecv_cbflag = true;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, NULL, NULL);
}
void t_connect_nullrecv(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_nullrecv_cbflag = false;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_connect_nullrecv_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_false(t_connect_nullrecv_cbflag);
	c = utcp_connect(a, 123, NULL, NULL);
	g_assert_nonnull(c);
	g_assert_true(t_connect_nullrecv_cbflag);

	// connection should be established
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);

	g_assert_cmpint(utcp_close(c), ==, 0);
	utcp_exit(a);
	utcp_exit(b);
}


int t_connect_preaccept_cbflags;
bool t_connect_preaccept_preaccept_cb(struct utcp *utcp, uint16_t port) {
	t_connect_preaccept_cbflags |= 1;
	g_assert_nonnull(utcp);
	g_assert_cmpuint(port, ==, 123);
	return true;
}
void t_connect_preaccept_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_connect_preaccept_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, NULL, NULL);
}
void t_connect_preaccept(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_connect_preaccept_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_connect_preaccept_accept_cb, t_connect_preaccept_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_connect_preaccept_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, NULL, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_connect_preaccept_cbflags, ==, 0x3);	// preaccept and accept called

	// connection should be established
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);

	g_assert_cmpint(utcp_close(c), ==, 0);
	utcp_exit(a);
	utcp_exit(b);
}


int t_send1_recvcnt;
ssize_t t_send1_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	if(t_send1_recvcnt) {
		// already called once
		g_assert_null(data);
		g_assert_cmpint(len, ==, 0);
	} else {
		g_assert_cmpstr(data, ==, "Hello");
		g_assert_cmpuint(len, ==, 6);
	}
	t_send1_recvcnt++;
	return len;
}
bool t_send1_preaccept_cb(struct utcp *utcp, uint16_t port) {
	g_assert_nonnull(utcp);
	return (port == 123);
}
void t_send1_accept_cb(struct utcp_connection *c, uint16_t port) {
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_send1_recv_cb_b, NULL);
}
void t_send1(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_send1_recvcnt = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_send1_accept_cb, t_send1_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmpint(t_send1_recvcnt, ==, 0);
	c = utcp_connect(a, 123, NULL, NULL);
	g_assert_nonnull(c);

	// connection should be established
	g_assert_cmpint(t_send1_recvcnt, ==, 0);	// recv_b not called
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);
	g_assert_cmpint(t_send1_recvcnt, ==, 1);	// recv_b called once

	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmpint(t_send1_recvcnt, ==, 2);	// recv_b called twice
	utcp_exit(a);
	utcp_exit(b);
}


int t_send2_recvcnt;
ssize_t t_send2_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	if(t_send2_recvcnt == 2) {
		g_assert_null(data);
		g_assert_cmpint(len, ==, 0);
	} else if(t_send2_recvcnt == 1) {
		g_assert_cmpstr(data, ==, "World!");
		g_assert_cmpuint(len, ==, 7);
	} else {
		g_assert_cmpint(t_send2_recvcnt, ==, 0);
		g_assert_cmpstr(data, ==, "Hello");
		g_assert_cmpuint(len, ==, 6);
	}
	t_send2_recvcnt++;
	return len;
}
bool t_send2_preaccept_cb(struct utcp *utcp, uint16_t port) {
	g_assert_nonnull(utcp);
	return (port == 123);
}
void t_send2_accept_cb(struct utcp_connection *c, uint16_t port) {
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_send2_recv_cb_b, NULL);
}
void t_send2(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_send2_recvcnt = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_send2_accept_cb, t_send2_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmpint(t_send2_recvcnt, ==, 0);
	c = utcp_connect(a, 123, NULL, NULL);
	g_assert_nonnull(c);

	// connection should be established
	g_assert_cmpint(t_send2_recvcnt, ==, 0);	// recv_b not called
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);
	g_assert_cmpint(t_send2_recvcnt, ==, 1);	// recv_b called once
	g_assert_cmpint(utcp_send(c, "World!", 7), ==, 7);
	g_assert_cmpint(t_send2_recvcnt, ==, 2);	// recv_b called twice

	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmpint(t_send2_recvcnt, ==, 3);	// recv_b called thrice
	utcp_exit(a);
	utcp_exit(b);
}


int t_send_echo_recvcnt_a;
int t_send_echo_recvcnt_b;
ssize_t t_send_echo_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	if(t_send_echo_recvcnt_a == 2) {
		g_assert_null(data);
		g_assert_cmpint(len, ==, 0);
	} else if(t_send_echo_recvcnt_a == 1) {
		g_assert_cmpstr(data, ==, "World!");
		g_assert_cmpuint(len, ==, 7);
	} else {
		g_assert_cmpint(t_send_echo_recvcnt_a, ==, 0);
		g_assert_cmpstr(data, ==, "Hello");
		g_assert_cmpuint(len, ==, 6);
	}
	t_send_echo_recvcnt_a++;
	return len;
}
ssize_t t_send_echo_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	if(t_send_echo_recvcnt_b == 2) {
		g_assert_null(data);
		g_assert_cmpint(len, ==, 0);
	} else if(t_send_echo_recvcnt_b == 1) {
		g_assert_cmpstr(data, ==, "World!");
		g_assert_cmpuint(len, ==, 7);
	} else {
		g_assert_cmpint(t_send_echo_recvcnt_b, ==, 0);
		g_assert_cmpstr(data, ==, "Hello");
		g_assert_cmpuint(len, ==, 6);
	}
	g_assert_cmpint(utcp_send(c, data, len), ==, len);
	t_send_echo_recvcnt_b++;
	return len;
}
bool t_send_echo_preaccept_cb(struct utcp *utcp, uint16_t port) {
	g_assert_nonnull(utcp);
	return (port == 123);
}
void t_send_echo_accept_cb(struct utcp_connection *c, uint16_t port) {
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_send_echo_recv_cb_b, NULL);
}
void t_send_echo(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_send_echo_recvcnt_a = 0;
	t_send_echo_recvcnt_a = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_send_echo_accept_cb, t_send_echo_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmpint(t_send_echo_recvcnt_a, ==, 0);
	g_assert_cmpint(t_send_echo_recvcnt_b, ==, 0);
	c = utcp_connect(a, 123, t_send_echo_recv_cb_a, NULL);
	g_assert_nonnull(c);

	// connection should be established
	g_assert_cmpint(t_send_echo_recvcnt_a, ==, 0);	// recv_a not called
	g_assert_cmpint(t_send_echo_recvcnt_b, ==, 0);	// recv_b not called
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);
	g_assert_cmpint(t_send_echo_recvcnt_a, ==, 1);	// recv_a called once
	g_assert_cmpint(t_send_echo_recvcnt_b, ==, 1);	// recv_b called once
	g_assert_cmpint(utcp_send(c, "World!", 7), ==, 7);
	g_assert_cmpint(t_send_echo_recvcnt_a, ==, 2);	// recv_a called twice
	g_assert_cmpint(t_send_echo_recvcnt_b, ==, 2);	// recv_b called twice

	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmpint(t_send_echo_recvcnt_a, ==, 2);	// recv_a NOT called again XXX?
	g_assert_cmpint(t_send_echo_recvcnt_b, ==, 3);	// recv_b called thrice

	utcp_exit(a);
	utcp_exit(b);
}


int t_send_big_recvcnt;
ssize_t t_send_big_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_send_big_recvcnt++;
	// XXX we don't send() something back, where does the ACK come from?
	return len;
}
bool t_send_big_preaccept_cb(struct utcp *utcp, uint16_t port) {
	g_assert_nonnull(utcp);
	return (port == 123);
}
void t_send_big_accept_cb(struct utcp_connection *c, uint16_t port) {
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_send_big_recv_cb_b, NULL);
}
void t_send_big(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_send_big_recvcnt = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_send_big_accept_cb, t_send_big_preaccept_cb, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_send_big_recvcnt, ==, 0);
	c = utcp_connect(a, 123, NULL, NULL);
	g_assert_nonnull(c);

	// connection should be established
	char buf[20480] = "buf";
	utcp_set_sndbuf(c, 10240);
	g_assert_cmpint(utcp_send(c, buf, sizeof buf), ==, sizeof buf);
		// XXX do we expect 20480 (sizeof buf) ro 10240 (sndbuf)?
	g_assert_cmphex(t_send_big_recvcnt, ==, 2);	// recv_b called twice

	g_assert_cmpint(utcp_close(c), ==, 0);
	utcp_exit(a);
	utcp_exit(b);
}


int t_close_cbflags;
struct utcp_connection *t_close_conn_b;
ssize_t t_close_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_close_cbflags |= 1;
	g_assert_cmpint(len, ==, 0);
	g_assert_cmpint(errno, ==, 0);
	g_assert_null(data);
	return len;
}
ssize_t t_close_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	g_assert_not_reached();
}
void t_close_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_close_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_close_recv_cb_b, NULL);
	t_close_conn_b = c;	// this is b's side of the connection
}
void t_close(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_close_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_close_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_close_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_close_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_close_cbflags, ==, 0x2); // only accept called

	// connection should be established
	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmphex(t_close_cbflags, ==, 0x3); // accept and recv_b called

	// try sending from a's side
	g_assert_cmpint(utcp_send(c, "Hello", 6), <, 0);
	g_assert_cmpint(utcp_close(c), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 0), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 1), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 2), <, 0);

	// try sending from b's side
	g_assert_cmpint(utcp_send(t_close_conn_b, "World!", 7), <, 0);
	g_assert_cmpint(utcp_close(t_close_conn_b), ==, 0);
	g_assert_cmpint(utcp_shutdown(t_close_conn_b, 0), <, 0);
	g_assert_cmpint(utcp_shutdown(t_close_conn_b, 1), <, 0);
	g_assert_cmpint(utcp_shutdown(t_close_conn_b, 2), <, 0);

	utcp_exit(a);
	utcp_exit(b);
}


int t_abort_cbflags;
struct utcp_connection *t_abort_conn_b;
ssize_t t_abort_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_abort_cbflags |= 1;
	g_assert_cmpint(len, ==, 0);
	g_assert_cmpint(errno, !=, 0);
	return len;
}
ssize_t t_abort_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	g_assert_not_reached();
}
void t_abort_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_abort_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_abort_recv_cb_b, NULL);
	t_abort_conn_b = c;	// this is b's side of the connection
}
void t_abort(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_abort_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_abort_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_abort_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_abort_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_abort_cbflags, ==, 0x2); // only accept called

	// connection should be established
	g_assert_cmpint(utcp_abort(c), ==, 0);
	g_assert_cmphex(t_abort_cbflags, ==, 0x3); // accept and recv_b called

	// try sending from a's side
	g_assert_cmpint(utcp_send(c, "Hello", 6), <, 0);
	g_assert_cmpint(utcp_close(c), <, 0);

	// try sending from b's side
	g_assert_cmpint(utcp_send(t_abort_conn_b, "World!", 7), <, 0);
	g_assert_cmpint(utcp_close(t_abort_conn_b), ==, 0);

	utcp_exit(a);
	utcp_exit(b);
}


int t_shutdown_rdwr_cbflags;
struct utcp_connection *t_shutdown_rdwr_conn_b;
ssize_t t_shutdown_rdwr_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_shutdown_rdwr_cbflags |= 1;
	g_assert_cmpint(len, ==, 0);
	g_assert_cmpint(errno, ==, 0);
	g_assert_null(data);
	return len;
}
ssize_t t_shutdown_rdwr_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	g_assert_not_reached();
}
void t_shutdown_rdwr_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_shutdown_rdwr_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_shutdown_rdwr_recv_cb_b, NULL);
	t_shutdown_rdwr_conn_b = c;	// this is b's side of the connection
}
void t_shutdown_rdwr(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_shutdown_rdwr_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_shutdown_rdwr_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_shutdown_rdwr_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_shutdown_rdwr_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_shutdown_rdwr_cbflags, ==, 0x2); // only accept called

	// connection should be established
	g_assert_cmpint(utcp_shutdown(c, 2), ==, 0);	// XXX 2 = SHUT_RDWR
	g_assert_cmphex(t_shutdown_rdwr_cbflags, ==, 0x3); // accept and recv_b called

	// try sending from a's side
	g_assert_cmpint(utcp_send(c, "Hello", 6), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 0), ==, 0);
	g_assert_cmpint(utcp_shutdown(c, 1), ==, 0);
	g_assert_cmpint(utcp_shutdown(c, 2), ==, 0);
	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmpint(utcp_shutdown(c, 0), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 1), <, 0);
	g_assert_cmpint(utcp_shutdown(c, 2), <, 0);

	// try sending from b's side
	g_assert_cmpint(utcp_send(t_shutdown_rdwr_conn_b, "World!", 7), <, 0);
		// XXX ^ calls recv_a, even though a shut down for reading
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 0), ==, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 1), ==, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 2), ==, 0);
	g_assert_cmpint(utcp_close(t_shutdown_rdwr_conn_b), ==, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 0), <, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 1), <, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_rdwr_conn_b, 2), <, 0);

	utcp_exit(a);
	utcp_exit(b);
}


int t_shutdown_rd_cbflags;
struct utcp_connection *t_shutdown_rd_conn_b;
ssize_t t_shutdown_rd_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	if(t_shutdown_rd_cbflags & 1) {
		g_assert_cmpint(len, ==, 0);
		g_assert_cmpint(errno, ==, 0);
		g_assert_null(data);
	}
	t_shutdown_rd_cbflags |= 1;
	return len;
}
ssize_t t_shutdown_rd_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	if(t_shutdown_rd_cbflags & 4) {
		g_assert_cmpint(len, ==, 0);
		g_assert_cmpint(errno, ==, 0);
		g_assert_null(data);
	}
	t_shutdown_rd_cbflags |= 4;
	return len;
}
void t_shutdown_rd_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_shutdown_rd_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_shutdown_rd_recv_cb_b, NULL);
	t_shutdown_rd_conn_b = c;	// this is b's side of the connection
}
void t_shutdown_rd(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_shutdown_rd_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_shutdown_rd_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_shutdown_rd_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x2); // only accept called

	// connection should be established
	g_assert_cmpint(utcp_shutdown(c, 0), ==, 0);	// XXX 0 = SHUT_RD
		// XXX ^ calls recv_b because utcp_shutdown ignores dir (always SHUT_RDWR)
	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x2); // accept and NOT recv_b called
	g_assert_cmpint(utcp_shutdown(c, 0), ==, 0);

	// try sending from a's side
	g_assert_cmpint(utcp_send(c, "Hello", 6), ==, 6);
	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x3); // accept and recv_b called

	// try sending from b's side
	g_assert_cmpint(utcp_send(t_shutdown_rd_conn_b, "World!", 7), <, 0);
	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x3); // recv_a NOT called
	g_assert_cmpint(utcp_shutdown(t_shutdown_rd_conn_b, 0), ==, 0);
	g_assert_cmphex(t_shutdown_rd_cbflags, ==, 0x7); // recv_a called

	g_assert_cmpint(utcp_close(c), ==, 0);	// calls recv_b(NULL)
	g_assert_cmpint(utcp_shutdown(c, 0), <, 0);
	g_assert_cmpint(utcp_close(t_shutdown_rd_conn_b), ==, 0);	// calls recv_a(NULL)
	g_assert_cmpint(utcp_shutdown(t_shutdown_rd_conn_b, 0), <, 0);

	utcp_exit(a);
	utcp_exit(b);
}


int t_shutdown_wr_cbflags;
struct utcp_connection *t_shutdown_wr_conn_b;
ssize_t t_shutdown_wr_recv_cb_b(struct utcp_connection *c, const void *data, size_t len) {
	t_shutdown_wr_cbflags |= 1;
	g_assert_cmpint(len, ==, 0);
	g_assert_cmpint(errno, ==, 0);
	g_assert_null(data);
	return len;
}
ssize_t t_shutdown_wr_recv_cb_a(struct utcp_connection *c, const void *data, size_t len) {
	if(t_shutdown_wr_cbflags & 4) {
		g_assert_cmpint(len, ==, 0);
		g_assert_cmpint(errno, ==, 0);
		g_assert_null(data);
	}
	t_shutdown_wr_cbflags |= 4;
	return len;
}
void t_shutdown_wr_accept_cb(struct utcp_connection *c, uint16_t port) {
	t_shutdown_wr_cbflags |= 2;
	g_assert_nonnull(c);
	g_assert_cmpuint(port, ==, 123);
	utcp_accept(c, t_shutdown_wr_recv_cb_b, NULL);
	t_shutdown_wr_conn_b = c;	// this is b's side of the connection
}
void t_shutdown_wr(void) {
	struct utcp *a, *b;
	struct utcp_connection *c;

	t_shutdown_wr_cbflags = 0;
	a = utcp_init(NULL, NULL, do_send, NULL);
	b = utcp_init(t_shutdown_wr_accept_cb, NULL, do_send, a);
	g_assert_nonnull(a);
	g_assert_nonnull(b);
	a->priv = b;

	g_assert_cmphex(t_shutdown_wr_cbflags, ==, 0x0);
	c = utcp_connect(a, 123, t_shutdown_wr_recv_cb_a, NULL);
	g_assert_nonnull(c);
	g_assert_cmphex(t_shutdown_wr_cbflags, ==, 0x2); // only accept called

	// connection should be established
	g_assert_cmpint(utcp_shutdown(c, 1), ==, 0);	// XXX 1 = SHUT_WR
	g_assert_cmphex(t_shutdown_wr_cbflags, ==, 0x3); // accept and recv_b called
	g_assert_cmpint(utcp_shutdown(c, 1), ==, 0);

	// try sending from a's side
	g_assert_cmpint(utcp_send(c, "Hello", 6), <, 0);

	// try sending from b's side
	g_assert_cmphex(t_shutdown_wr_cbflags, ==, 0x3); // recv_a not called
	g_assert_cmpint(utcp_send(t_shutdown_wr_conn_b, "World!", 7), ==, 7);
	g_assert_cmphex(t_shutdown_wr_cbflags, ==, 0x7); // recv_a called
	g_assert_cmpint(utcp_shutdown(t_shutdown_wr_conn_b, 1), ==, 0);

	g_assert_cmpint(utcp_close(c), ==, 0);
	g_assert_cmpint(utcp_shutdown(c, 1), <, 0);
	g_assert_cmpint(utcp_close(t_shutdown_wr_conn_b), ==, 0);
	g_assert_cmpint(utcp_shutdown(t_shutdown_wr_conn_b, 1), <, 0);

	utcp_exit(a);
	utcp_exit(b);
}




int main(int argc, char *argv[]) {
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/init/nullsend", t_init_nullsend);
	g_test_add_func("/connect/nullaccept", t_connect_nullaccept);
	g_test_add_func("/connect/nullpreaccept", t_connect_nullpreaccept);
	g_test_add_func("/connect/closed", t_connect_closed);
	g_test_add_func("/connect/open", t_connect_open);
	g_test_add_func("/connect/nullrecv", t_connect_nullrecv);
	g_test_add_func("/connect/preaccept", t_connect_preaccept);
	g_test_add_func("/send/1", t_send1);
	g_test_add_func("/send/2", t_send2);
	g_test_add_func("/send/echo", t_send_echo);
	g_test_add_func("/send/big", t_send_big);
	g_test_add_func("/close", t_close);
	g_test_add_func("/abort", t_abort);
	g_test_add_func("/shutdown/rdwr", t_shutdown_rdwr);
	g_test_add_func("/shutdown/rd", t_shutdown_rd);
	g_test_add_func("/shutdown/wr", t_shutdown_wr);

	g_test_run();
	return 0;
}
