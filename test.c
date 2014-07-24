#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>


#include "utcp.h"

struct utcp_connection *c;
int dir = 3;
bool running = true;

int do_recv(struct utcp_connection *c, void *data, size_t len) {
	if(!data || !len) {
		if(errno)
			fprintf(stderr, "Error: %s\n", strerror(errno));
		else {
			dir &= ~2;
			fprintf(stderr, "Connection closed by peer\n");
		}
		return 0;
	}
	return write(0, data, len);
}

void do_accept(struct utcp_connection *nc, void *data, size_t len) {
	utcp_accept(nc, do_recv, NULL);
	c = nc;
}

int do_send(struct utcp *utcp, void *data, size_t len) {
	int s = *(int *)utcp->priv;
	return send(s, data, len, MSG_DONTWAIT);
}

int main(int argc, char *argv[]) {
	srand(time(NULL));

	if(argc < 2 || argc > 3)
		return 1;

	bool server = argc == 2;
	bool connected = false;

	struct addrinfo *ai;
	struct addrinfo hint = {
		.ai_flags = server ? AI_PASSIVE : 0,
		.ai_socktype = SOCK_DGRAM,
	};

	getaddrinfo(server ? NULL : argv[1], server ? argv[1] : argv[2], &hint, &ai);
	if(!ai)
		return 1;

	int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(s < 0)
		return 1;

	if(server) {
		if(bind(s, ai->ai_addr, ai->ai_addrlen))
			return 1;
	} else {
		if(connect(s, ai->ai_addr, ai->ai_addrlen))
			return 1;
		connected = true;
	}

	struct utcp *u = utcp_init(server ? do_accept : NULL, NULL, do_send, &s);
	if(!u)
		return 1;

	if(!server)
		c = utcp_connect(u, "test", 4, do_recv, NULL);

	struct pollfd fds[2] = {
		{.fd = 0, .events = POLLIN | POLLERR | POLLHUP},
		{.fd = s, .events = POLLIN | POLLERR | POLLHUP},
	};

	char buf[1024];

	while(dir) {
		int r = poll(fds, 2, 1000);
		if(!r) {
			utcp_timeout(u);
			continue;
		}

		if(fds[0].revents) {
			int len = read(0, buf, sizeof buf);
			if(len <= 0) {
				fds[0].fd = -1;
				dir &= ~1;
				if(c)
					utcp_shutdown(c, SHUT_WR);
				if(len < 0)
					break;
				else
					continue;
			}
			if(c)
				utcp_send(c, buf, len);
		}

		if(fds[1].revents) {
			struct sockaddr_storage ss;
			socklen_t sl;
			int len = recvfrom(s, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&ss, &sl);
			if(len <= 0)
				break;
			if(!connected)
				if(!connect(s, (struct sockaddr *)&ss, sl))
					connected = true;
			utcp_recv(u, buf, len);
		}
	};

	utcp_close(c);
	utcp_exit(u);

	return 0;
}
