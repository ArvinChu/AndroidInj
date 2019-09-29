/*
 * libmynet.c
 *
 *  Created on: 2013-1-17
 *      Author: d
 */

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/poll.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "debug.h"

int read_end = 0;

int my_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
	LOGI("my_connect...");
    return -1;
}

void send_mouse_position_to_server(int x, int y) {
	LOGI("send_mouse_position_to_server...do nothing");
}

void read_pipe() {
	int fd;
	char *pipe_name = "/data/hook_poll";
	if (read_end == 0) {
		if(mkfifo(pipe_name, 0666) < 0 && errno != EEXIST) {
			LOGI("read_pipe mkfifo %s failed", pipe_name);
			return;
		}
		LOGI("read_pipe wait...");
		// waiting write open...
		if((fd = open(pipe_name, O_RDONLY)) < 0) {
			LOGI("read_pipe open %s failed", pipe_name);
			return;
		}

		close(fd);
		read_end = 1;
		LOGI("read_pipe end");
	}
}

int poll(struct pollfd *fd, unsigned int nfds, int timeout) {
	read_pipe();
	return 1;
}

