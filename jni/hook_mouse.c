#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include "inj/debug.h"

int read_end = 0;

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
