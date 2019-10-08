/*
 * inject.c
 *
 *  Created on: Jun 4, 2011
 *      Author: d
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include "utils.h"
#include <signal.h>
#include <sys/types.h>
#ifdef ANDROID
//#include <linker.h>
#endif
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <jni.h>

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

struct process_info processinfo;

void call_shit(struct elf_info *einfo) {
    unsigned long addr2 = 0;
    unsigned long rel_addr = find_sym_in_rel(einfo, "math_shit");
    regs_t regs;
    ptrace_read(einfo->pid, rel_addr, &addr2, sizeof(long));
    LOGI("math_shit rel addr\t %lx\n", rel_addr);
    LOGI("addr2 is \t %lx\n", addr2);
    ptrace_readreg(einfo->pid, &regs);
    ptrace_dump_regs(&regs,"before call to call_shit\n");
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr = 0;
#endif
    regs.ARM_r0 = 5;
    regs.ARM_r1 = 6;
    regs.ARM_r2 = 7;
    regs.ARM_r3 = 8;
    {
        int a5 = 9;
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        ptrace_push(einfo->pid, &regs, &a5, 4);
        a5 = 10;
        ptrace_push(einfo->pid, &regs, &a5, 4);
    }
    regs.ARM_pc = addr2;
    ptrace_writereg(einfo->pid, &regs);
    ptrace_cont(einfo->pid);
    LOGI("done %d\n",  ptrace_wait_for_signal(einfo->pid,SIGSEGV));
    ptrace_readreg(einfo->pid, &regs);
    ptrace_dump_regs(&regs,"before return call_shit\n");
}

/**
 * 如果hook进程被阻塞，则通知其结束阻塞
 */
void write_pipe() {
	int fd;
	char *pipe_name = "/data/hook_poll";

	if((fd = open(pipe_name, O_WRONLY | O_NONBLOCK)) < 0) {
		LOGE("write_pipe open %s failed! errno %d", pipe_name, errno);
		errno = 0;
		return;
	}
	close(fd);
	// waiting read
	usleep(100000);
}

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

/**
 * 使用dlopen加载hook库文件，并返回hook函数地址
 *
 * @param function_name : hook函数名称
 * @param load_library_path : hook库文件路径
 *
 * @return hook函数地址
 */
unsigned long find_symbol_address(int pid, const char *function_name, const char *load_library_path) {
	dl_fl_t *dlinfo = NULL;
	unsigned long symbol_address = 0;

	dlinfo = ptrace_find_dlinfo(pid);
	if (dlinfo != NULL) {
		processinfo.handle = ptrace_dlopen(pid, load_library_path, 1);
		if (processinfo.handle != NULL) {
			symbol_address = (unsigned long) ptrace_dlsym(pid, processinfo.handle, function_name);
		}
	}

	return symbol_address;
}

/**
 * hook目标进程中目标so库中的目标函数
 *
 * @param target_process_name : 目标进程名
 * @param function_name : 目标/替换函数名
 * @param target_so_name : 目标so文件名
 * @param load_library_path : hook库文件路径
 *
 * @return 1 : hook成功; other : hook失败
 */
int inject_remote_process(const char *target_process_name, const char *function_name, const char *target_so_name, const char *load_library_path) {
	int pid = -1, result = -1;
	unsigned long symbol_address = 0;

	pid = find_pid_of(target_process_name);
	processinfo.pid = pid;
	pint(processinfo.pid);
	if (pid > 0) {
		ptrace_attach(pid);
		symbol_address = find_symbol_address(pid, function_name, load_library_path );
		pint(symbol_address);
		if (symbol_address > 0) {
			processinfo.function_address = get_function_address(pid, function_name, target_so_name);
			pint(processinfo.function_address);
			if (processinfo.function_address > 0) {
				ptrace_read(pid, processinfo.function_address, &processinfo.function_data, 4);
				pint(processinfo.function_data);
				ptrace_write(pid, processinfo.function_address, &symbol_address, 4);
				result = 1;
			}
		}
		ptrace_detach(pid);
	}

	return result;
}

/**
 * 恢复hook进程的状态(包含寄存器、函数)
 */
void restore_remote_process() {
	write_pipe();

	if (processinfo.pid > 0) {
		ptrace_attach(processinfo.pid);
		if (processinfo.function_address > 0) {
			ptrace_write(processinfo.pid, processinfo.function_address, &processinfo.function_data, 4);
		}
		if (processinfo.handle != NULL) {
			ptrace_dlclose(processinfo.pid, processinfo.handle);
		}
		ptrace_detach(processinfo.pid);
		processinfo.pid = -1;
	}
}

int main(int argc, char *argv[]) {
//	int i = 99;
//	while (i++ < 100) {
//		inject_remote_process("com.ruijie.rccstu:RccRemoteProcess", "poll", "libspice.so", "/system/lib/libmynet.so");
//		sleep(10);
//		restore_remote_process();
//		sleep(5);
//	}
	wait_client_message();

    // end
    exit(0);
}
