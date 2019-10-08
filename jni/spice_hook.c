#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "cn_com_ruijie_classmanager_jni_SpiceHook.h"

#include "inj/debug.h"

const char *SOCKET_NAME = "/data/hook";
const char *SO_FILE = "libspice.so";
const char *TARGET_PROCESS_NAME = "com.ruijie.rccstu:RccRemoteProcess";
const char *SERVER_PROCESS_NAME = "/data/inj/inj";
#define ERROR -1

int clientfd = -1;
char result[2] = {0};
struct sockaddr_un serveraddr;

/**
 * 根据进程名称查找进程ID
 *
 * @param process_name : 进程名称
 *
 * @return 进程ID
 */
int find_pid_of(const char *process_name) {
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

int create_socket() {
	int sockfd = -1;
	struct sockaddr_un clientaddr;
	if ((sockfd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		LOGE("create_socket...fail to create socket! %s", strerror(errno));
	}
	bzero(&clientaddr, sizeof(clientaddr));
	clientaddr.sun_family = AF_LOCAL;
	memcpy(clientaddr.sun_path, "\0hook", 5);
	if (bind(sockfd, (struct sockaddr*) &clientaddr, sizeof(clientaddr)) < 0) {
		LOGE("create_socket...fail to bind! %s", strerror(errno));
		close(sockfd);
		sockfd = -1;
	} else {
		bzero(&serveraddr, sizeof(serveraddr));
		serveraddr.sun_family = AF_LOCAL;
		strncpy(serveraddr.sun_path, SOCKET_NAME, sizeof(serveraddr.sun_path)-1);
	}
	return sockfd;
}

int send_message(int socketfd, char *message) {
	LOGI("send_message...%s", message);
	int length = sendto(socketfd, message, strlen(message), 0, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
	if ( length < 0) {
		LOGE("sendto error...%s", strerror(errno));
	}

	return length;
}

int check_server() {
	clientfd = create_socket();
	if (clientfd > 0) {
		char *message = "heartbeat";
		if (send_message(clientfd, message) > 0) {
			if (recvfrom(clientfd, result, 2, 0, NULL, NULL) > 0
					&& atoi(result) == 1) {
				return clientfd;
			}
		}
	}
	LOGE("check_server...%s %d", strerror(errno), atoi(result));
	close(clientfd);
	clientfd = -1;
	return clientfd;
}

JNIEXPORT jint JNICALL Java_cn_com_ruijie_classmanager_jni_SpiceHook_init
  (JNIEnv *env, jclass obj) {
	int count = 0;
	while (count++ < 3) {
		int pid = find_pid_of(SERVER_PROCESS_NAME);
		if (pid < 1)
			pid = fork();
		if (pid < 0) {
			LOGE("init fork child process failed!");
			continue;
		} else if (pid == 0) {
			LOGI("init in child process...");
			if (execl("/system/bin/sh", "su", "-c", "/data/inj/inj", NULL) < 0) {
				LOGE("init child process...%s", strerror(errno));
			}
		} else {
			LOGI("init in parent process...");
			sleep(3);
			if (check_server() > 0)
				break;
		}
	}

	return clientfd;
}

JNIEXPORT jint JNICALL Java_cn_com_ruijie_classmanager_jni_SpiceHook_disableMouse
  (JNIEnv *env, jclass obj) {
	LOGI("call disable");
	if (clientfd > 0) {
		char *hook = "hook com.ruijie.rccstu:RccRemoteProcess poll libspice.so /data/data/com.ruijie.rccstu/lib/libhook_mouse.so";
		if (send_message(clientfd, hook) > 0) {
			if (recvfrom(clientfd, result, 2, 0, NULL, NULL) > 0) {
				return atoi(result);
			}
		}
	}
	LOGE("disableMouse...%s %d", strerror(errno), atoi(result));
	return -1;
}

JNIEXPORT jint JNICALL Java_cn_com_ruijie_classmanager_jni_SpiceHook_enableMouse
  (JNIEnv *env, jclass obj) {
	LOGI("call enable");
	if (clientfd > 0) {
		char *hook = "restore";
		if (send_message(clientfd, hook) > 0) {
			if (recvfrom(clientfd, result, 2, 0, NULL, NULL) > 0) {
				return atoi(result);
			}
		}
	}
	LOGE("enableMouse...%s %d", strerror(errno), atoi(result));
	return -1;
}


