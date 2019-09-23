/*
 * ptrace.c
 *
 *  Created on: Jun 4, 2011
 *      Author: d
 */

#include <stdio.h>
#include <sys/ptrace.h>

#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#ifdef ANDROID
#include <linux/user.h>
#else
#include <sys/user.h>
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <utils.h>

#include <stdarg.h>
#include "linker.h"

static regs_t oldregs;

dl_fl_t ldl;

/**
 * 打印寄存器值
 */
void ptrace_dump_regs(regs_t *regs, char *msg) {
//	struct pt_regs {
//		long uregs[18];
//	};
//	#define ARM_cpsr uregs[16]
//	#define ARM_pc uregs[15]
//	#define ARM_lr uregs[14]
//	#define ARM_sp uregs[13]
//	#define ARM_ip uregs[12]
//	#define ARM_fp uregs[11]
//	#define ARM_r10 uregs[10]
//	#define ARM_r9 uregs[9]
//	#define ARM_r8 uregs[8]
//	#define ARM_r7 uregs[7]
//	#define ARM_r6 uregs[6]
//	#define ARM_r5 uregs[5]
//	#define ARM_r4 uregs[4]
//	#define ARM_r3 uregs[3]
//	#define ARM_r2 uregs[2]
//	#define ARM_r1 uregs[1]
//	#define ARM_r0 uregs[0]
//	#define ARM_ORIG_r0 uregs[17]
    int i = 0;
    LOGI("------regs %s-----\n", msg);
    for (i = 0; i < 18; i++) {
    	LOGI("r[%02d]=%lx\n", i, regs->uregs[i]);
    }
}

/**
 * 跟踪远程进程，并使之进入暂停状态
 *
 * @param pid : 进程ID
 */
void ptrace_attach(int pid) {
    regs_t regs;
    int status = 0;
	// 使调用进程变成被跟踪进程的父进程(用ps可以看到，被跟踪进程的真正父进程是ID为getpid()的进程)，建立跟踪关系
    // 此时任何传递给被跟踪进程的信号(除了会直接杀死进程的SIGKILL信号)都会使得这个进程进入暂停状态
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL ) < 0) {
    	LOGE("ptrace_attach");
        exit(-1);
    }
    LOGI("ptrace_wait_for_signal");
    // 暂停被跟踪进程
    status = ptrace_wait_for_signal(pid, SIGSTOP);
    LOGI("ptrace_wait_for_signal: %d %d\n", __LINE__, status);
    //waitpid(pid, NULL, WUNTRACED);

    // 读取被跟踪进程的寄存器值
    ptrace_readreg(pid, &regs);
    // 保存寄存器值
    memcpy(&oldregs, &regs, sizeof(regs));
    ptrace_dump_regs(&oldregs, "old regs");

#ifdef ANDROID
#ifdef THUMB
    regs.ARM_pc = 0x11;
    // 设置Thumb指令集
    regs.ARM_cpsr |= 0x30;
#else
    regs.ARM_pc= 0;
#endif
#else
    regs.rip = 0;
#endif
    // 设置寄存器值
    ptrace_writereg(pid, &regs);
    // 继续运行被跟踪进程
    ptrace_cont(pid);

    LOGI("waiting.. sigal...\n");
    // 暂停被跟踪进程
    status = ptrace_wait_for_signal(pid, SIGSEGV);
    LOGI("ptrace_wait_for_signal2: %d %d\n", __LINE__, status);
}

/**
 * 使进程继续运行
 *
 * @param pid : 进程ID
 */
void ptrace_cont(int pid) {
	// 让进程继续运行
    if (ptrace(PTRACE_CONT, pid, NULL, NULL ) < 0) {
    	LOGE("ptrace_cont");
        exit(-1);
    }

    //while (!WIFSTOPPED(stat))
    //    waitpid(pid, &stat, WNOHANG);
}

/**
 * 恢复远程进程寄存器值并停止跟踪
 *
 * @param pid : 进程ID
 */
void ptrace_detach(int pid) {
	// 还原寄存器值
    ptrace_writereg(pid, &oldregs);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL ) < 0) {
    	LOGE("ptrace_detach");
        exit(-1);
    }
    LOGI("ptrace_detach end");
}

// PTRACE_POKETEXT: Copy the word data to the address addr in the tracee's memory.
// 32位机器中 a word是4个字节 == long/unsigned long
/**
 * 将vptr指向地址的数据写入目标进程中addr指向的地址，写入数据长度为len
 * @param pid : 目标进程ID
 * @param addr : 目标起始地址
 * @param vptr : 源数据起始地址
 * @param len : 写入数据长度
 */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len) {
    int count;
    long word;
    void *src = (long*) vptr;
    count = 0;

    // 循环写入
    while (count < len) {
    	// 每次从vptr中读取4个字节到word
        memcpy(&word, src + count, sizeof(word));
        // 将word写入addr
        word = ptrace(PTRACE_POKETEXT, pid, (void*) (addr + count), (void*) word);
        count += 4;

        if (errno != 0)
            LOGE("ptrace_write failed\t %ld\n", addr + count);
    }
}


// PTRACE_PEEKTEXT: Read a word at the address addr in the tracee's memory, returning the word as the result of the ptrace() call.
// 32位机器中 a word是4个字节 == long/unsigned long
/**
 * 将目标进程中addr指向地址的数据读取到vptr指向的地址中，读取数据长度为len
 * @param pid : 目标进程ID
 * @param addr : 源数据起始地址
 * @param vptr : 目标起始地址
 * @param len : 读取数据长度
 */
void ptrace_read(int pid, unsigned long addr, void *vptr, int len) {
    int i, count;
    long word;
    unsigned long *ptr = (unsigned long *) vptr;

    i = count = 0;
    // 循环读取
    while (count < len) {
        word = ptrace(PTRACE_PEEKTEXT, pid, (void*) (addr + count), NULL);
        count += 4;
        ptr[i++] = word;
    }
}

/**
 * 从目标进程中addr指向的地址读取数据(最多读取64个字节)并返回
 * @param pid : 目标进程ID
 * @param addr : 源数据起始地址
 *
 * @return 返回读取的字符串数据
 */
char * ptrace_readstr(int pid, unsigned long addr) {
	// 64可以根据实际函数名长度加以修改
    char *str = (char *) malloc(64);
    int i, count;
    long word;
    char *pa;

    i = count = 0;
    pa = (char *) &word;

    // 从addr指向的地址中读取64个字节数据，如果遇到‘\0’，则停止读取
    while (i <= 60) {
    	// 每次读取的数据将覆盖word之前的内容
        word = ptrace(PTRACE_PEEKTEXT, pid, (void*) (addr + count), NULL);
        count += 4;

        if (pa[0] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[0];

        if (pa[1] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[1];

        if (pa[2] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[2];

        if (pa[3] == '\0') {
            str[i] = '\0';
            break;
        } else
            str[i++] = pa[3];
    }
    return str;
}

/**
 * 读取寄存器值
 */
void ptrace_readreg(int pid, regs_t *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs))
        LOGE("*** ptrace_readreg error ***\n");
}

/**
 * 设置寄存器值
 */
void ptrace_writereg(int pid, regs_t *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs))
        LOGE("*** ptrace_writereg error ***\n");
}

/**
 * 将函数参数压栈
 * 函数传参规则: 前四个参数分别由寄存器r0、r1、r2、r3存放，超过四个参数则压入堆栈
 */
unsigned long ptrace_push(int pid, regs_t *regs, void *paddr, int size) {
#ifdef ANDROID
    unsigned long arm_sp;
    arm_sp = regs->ARM_sp;
    arm_sp -= size;
    arm_sp = arm_sp - arm_sp % 4;
    regs->ARM_sp= arm_sp;
    ptrace_write(pid, arm_sp, paddr, size);
    return arm_sp;
#else
    unsigned long esp;
    regs_t regs;
    ptrace_readreg(pid, &regs);
    esp = regs.esp;
    esp -= size;
    esp = esp - esp % 4;
    regs.esp = esp;
    ptrace_writereg(pid, &regs);
    ptrace_write(pid, esp, paddr, size);
    return esp;
#endif
}

long ptrace_stack_alloc(pid_t pid, regs_t *regs, int size) {
    unsigned long arm_sp;
    arm_sp = regs->ARM_sp;
    arm_sp -= size;
    arm_sp = arm_sp - arm_sp % 4;
    regs->ARM_sp= arm_sp;
    return arm_sp;
}

/**
 * 调用进程的dlopen函数
 *
 * @param pid : 进程ID
 * @param filename : so文件路径
 * @param flag : dlopen的参数
 */
void *ptrace_dlopen(pid_t pid, const char *filename, int flag) {
#ifdef ANDROID
    regs_t regs;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_dlopen\n");
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= (long)ptrace_push(pid, &regs, (void*)filename, strlen(filename) + 1);
    regs.ARM_r1= flag;
    regs.ARM_pc= ldl.l_dlopen;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    LOGI("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_call\n");
    return (void*) regs.ARM_r0;
#endif
}

/**
 * 调用进程的dlsym函数
 *
 * @param pid : 进程ID
 * @param handle : dlopen返回的handle
 * @param symbol : dlsym的参数
 */
void *ptrace_dlsym(pid_t pid, void *handle, const char *symbol) {
#ifdef ANDROID
    regs_t regs;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_dlsym\n");
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= (long)handle;
    regs.ARM_r1= (long)ptrace_push(pid, &regs, (void*)symbol, strlen(symbol) + 1);
    regs.ARM_pc= ldl.l_dlsym;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    LOGI("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_dlsym\n");
    return (void*) regs.ARM_r0;
#endif
}


/**
 * 调用进程的dlclose函数
 *
 * @param pid : 进程ID
 * @param handle : dlopen返回的handle
 */
int ptrace_dlclose(pid_t pid, void *handle) {
#ifdef ANDROID
    regs_t regs;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_dlclose\n");
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= (long)handle;
    regs.ARM_pc= ldl.l_dlclose;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    LOGI("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_dlclose\n");
    return (void*) regs.ARM_r0;
#endif
}

int ptrace_mymath_add(pid_t pid, long mymath_add_addr, int a, int b) {
#ifdef ANDROID
    regs_t regs;
    //int stat;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before call to ptrace_mymath_add\n");

#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif

    regs.ARM_r0= a;
    regs.ARM_r1= b;

    regs.ARM_pc= mymath_add_addr;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    LOGI("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_mymath_add\n");
    return regs.ARM_r0;
#endif
}

int ptrace_call(int pid, long proc, int argc, ptrace_arg *argv) {
    int i = 0;
#define ARGS_MAX 64
    regs_t regs;
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before ptrace_call\n");

    /*prepare stacks*/
    for (i = 0; i < argc; i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_STR) {
            arg->_stackid = ptrace_push(pid, &regs, arg->s, strlen(arg->s) + 1);
        } else if (arg->type == PAT_MEM) {
            //printf("push data %p to stack[%d] :%d \n", arg->mem.addr, stackcnt, *((int*)arg->mem.addr));
            arg->_stackid = ptrace_push(pid, &regs, arg->mem.addr, arg->mem.size);
        }
    }
    for (i = 0; (i < 4) && (i < argc); i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_INT) {
            regs.uregs[i] = arg->i;
        } else if (arg->type == PAT_STR) {
            regs.uregs[i] = arg->_stackid;
        } else if (arg->type == PAT_MEM) {
            regs.uregs[i] = arg->_stackid;
        } else {
            LOGE("unkonwn arg type\n");
        }
    }

    for (i = argc - 1; i >= 4; i--) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_INT) {
            ptrace_push(pid, &regs, &arg->i, sizeof(int));
        } else if (arg->type == PAT_STR) {
            ptrace_push(pid, &regs, &arg->_stackid, sizeof(unsigned long));
        } else if (arg->type == PAT_MEM) {
            ptrace_push(pid, &regs, &arg->_stackid, sizeof(unsigned long));
        } else {
            LOGE("unkonwn arg type\n");
        }
    }
#ifdef THUMB
    regs.ARM_lr = 1;
#else
    regs.ARM_lr= 0;
#endif
    regs.ARM_pc= proc;
    ptrace_writereg(pid, &regs);
    ptrace_cont(pid);
    LOGI("done %d\n", ptrace_wait_for_signal(pid, SIGSEGV));
    ptrace_readreg(pid, &regs);
    ptrace_dump_regs(&regs, "before return ptrace_call\n");

    //sync memory
    for (i = 0; i < argc; i++) {
        ptrace_arg *arg = &argv[i];
        if (arg->type == PAT_STR) {
        } else if (arg->type == PAT_MEM) {
            ptrace_read(pid, arg->_stackid, arg->mem.addr, arg->mem.size);
        }
    }

    return regs.ARM_r0;
}

/**
 * 暂停进程的执行
 * @param pid : 进程ID
 * @param signal : 信号编号
 *
 * @return 1 : 暂停成功且暂停的信号为signal; 否则返回0
 */
int ptrace_wait_for_signal(int pid, int signal) {
    int status;
    pid_t res;
    // 暂停目标进程的执行
    res = waitpid(pid, &status, 0);
    // 如果暂停成功，则waitpid返回pid，且WIFSTOPPED(status)为true
    if (res != pid || !WIFSTOPPED (status))
        return 0;
    // WSTOPSIG(status)获取使进程暂停的信号编号
    return WSTOPSIG (status) == signal;
}

/**
 * 获取进程中/system/bin/linker模块的地址范围（Android系统中该模块包含dlopen、dlsym与dlclose函数）
 */
static Elf32_Addr get_linker_base(int pid, Elf32_Addr *base_start, Elf32_Addr *base_end) {
    unsigned long base = 0;
    char mapname[FILENAME_MAX];
    memset(mapname, 0, FILENAME_MAX);
    snprintf(mapname, FILENAME_MAX, "/proc/%d/maps", pid);
    FILE *file = fopen(mapname, "r");
    *base_start = *base_end = 0;
    if (file) {
        //400a4000-400b9000 r-xp 00000000 103:00 139       /system/bin/linker
        while (1) {
            unsigned int atleast = 32;
            int xpos = 20;
            char startbuf[9];
            char endbuf[9];
            char line[FILENAME_MAX];
            memset(line, 0, FILENAME_MAX);
            char *linestr = fgets(line, FILENAME_MAX, file);
            if (!linestr) {
                break;
            }
            LOGI("........%s <--\n", line);
            if (strlen(line) > atleast && strstr(line, "/system/bin/linker")) {
                memset(startbuf, 0, sizeof(startbuf));
                memset(endbuf, 0, sizeof(endbuf));

                memcpy(startbuf, line, 8);
                memcpy(endbuf, &line[8 + 1], 8);
                if (*base_start == 0) {
                    *base_start = strtoul(startbuf, NULL, 16);
                    *base_end = strtoul(endbuf, NULL, 16);
                    base = *base_start;
                } else {
                    *base_end = strtoul(endbuf, NULL, 16);
                }
            }
        }
        fclose(file);
    }
    return base;
}

/**
 * 获取进程中dlopen、dlsym、dlclose函数地址
 * (网上有另外一种方法计算dlopen等函数的地址)
 *
 * @param pid : 进程ID
 *
 * 注: struct soinfo的定义
 */
dl_fl_t *ptrace_find_dlinfo(int pid) {
    Elf32_Sym sym;
    Elf32_Addr addr;
    struct soinfo lsi;
#define LIBDLSO "libdl.so"
    Elf32_Addr base_start = 0;
    Elf32_Addr base_end = 0;
    Elf32_Addr base = get_linker_base(pid, &base_start, &base_end);

    if (base == 0) {
    	LOGE("no linker found\n");
        return NULL ;
    } else {
    	LOGI("search libdl.so from %08u to %08u\n", base_start, base_end);
    }

    for (addr = base_start; addr < base_end; addr += 4) {
        char soname[strlen(LIBDLSO)];
        Elf32_Addr off = 0;

        ptrace_read(pid, addr, soname, strlen(LIBDLSO));
        if (strncmp(LIBDLSO, soname, strlen(LIBDLSO))) {
            continue;
        }

        LOGI("soinfo found at %08u\n", addr);
        LOGI("symtab: %p\n", lsi.symtab);
        ptrace_read(pid, addr, &lsi, sizeof(lsi));

        off = (Elf32_Addr)lsi.symtab;

        ptrace_read(pid, off, &sym, sizeof(sym));
        //just skip
        off += sizeof(sym);

        ptrace_read(pid, off, &sym, sizeof(sym));
        ldl.l_dlopen = sym.st_value;
        off += sizeof(sym);

        ptrace_read(pid, off, &sym, sizeof(sym));
        ldl.l_dlclose = sym.st_value;
        off += sizeof(sym);

        ptrace_read(pid, off, &sym, sizeof(sym));
        ldl.l_dlsym = sym.st_value;
        off += sizeof(sym);

        LOGI("dlopen addr %p\n", (void*) ldl.l_dlopen);
        LOGI("dlclose addr %p\n", (void*) ldl.l_dlclose);
        LOGI("dlsym addr %p\n", (void*) ldl.l_dlsym);
        return &ldl;
    }
    LOGE("%s not found!\n", LIBDLSO);
    return NULL;
}

