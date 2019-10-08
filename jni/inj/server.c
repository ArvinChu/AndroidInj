#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <errno.h>

#include "utils.h"
#include "debug.h"

const char *SOCKET_NAME = "/data/hook";
#define MAXLEN 1024 /* 单次最大发送缓冲区为1K */
char buf[MAXLEN];
struct sockaddr_un clientaddr;

int create_socket() {
	int sockfd = -1;
	struct sockaddr_un bindaddr;
	if ((sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		LOGE("create_socket...fail to create socket! %s", strerror(errno));
	}
	unlink(SOCKET_NAME);
	bzero(&bindaddr, sizeof(bindaddr));
	bindaddr.sun_family = AF_LOCAL;
	strncpy(bindaddr.sun_path, SOCKET_NAME, sizeof(bindaddr.sun_path)-1);
	if (bind(sockfd, (struct sockaddr*) &bindaddr, sizeof(bindaddr)) < 0) {
		LOGE("create_socket...fail to bind! %s", strerror(errno));
		close(sockfd);
		sockfd = -1;
	}

	return sockfd;
}

int send_message(int socketfd, char *message) {
	LOGI("send_message...%s", message);
	int length = sendto(socketfd, message, strlen(message), 0, (struct sockaddr *) &clientaddr, sizeof(clientaddr));
	if ( length< 0) {
		LOGE("sendto error...%s", strerror(errno));
	}
	sleep(1);
	return length;
}

int wait_client_message() {
	int serverfd = -1;
	int len = sizeof(clientaddr);
start:
	while(1) {
		serverfd = create_socket();
		if (serverfd <= 0) {
			sleep(2);
			continue;
		} else {
			break;
		}
	}

	// read and parse message
	while (1) {
		LOGI("recvfrom message...waiting");
		memset(buf, 0, sizeof(buf));
		int length = recvfrom(serverfd, buf, MAXLEN, 0, (struct sockaddr*) &clientaddr, &len);
		if (length < 0) {
			LOGE("recvfrom error...%s", strerror(errno));
			break;
		} else {
			if (length == MAXLEN && buf[MAXLEN] != '\0') {
				LOGE("recvfrom error...message too large!");
			} else {
				LOGI("recvfrom message...%s", buf);
				int result = -1;
				char type[20] = {0};
				char *body = NULL;

				if (strchr(buf, ' ') != NULL) {
					body = strchr(buf, ' ') + 1;
					strncpy(type, buf, length - strlen(body) - 1);
				} else {
					strncpy(type, buf, length);
				}

				if (strcmp("heartbeat", type) == 0) {
					result = 1;
				} else if (strcmp("command", type) == 0) {
					result = -1;
				} else if (strcmp("hook", type) == 0) {
					char target_process_name[50] = {0};
					char function_name[20] = {0};
					char target_so_name[20] = {0};
					char load_library_path[100] = {0};
					sscanf(body, "%s %s %s %s", target_process_name, function_name, target_so_name, load_library_path);
					result = inject_remote_process(target_process_name, function_name, target_so_name, load_library_path);
				} else if (strcmp("restore", type) == 0) {
					restore_remote_process();
					result = 1;
				}

				char ret[2] = {0};
				sprintf(ret, "%d", result);
				send_message(serverfd, ret);
			}
		}
	}

	close(serverfd);
	goto start;

	return -1;
}
