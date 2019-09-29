/*
 * ptrace.h
 *
 *  Created on: Jun 4, 2011
 *      Author: d
 */

#ifndef PTRACE_H_
#define PTRACE_H_



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#ifdef ANDROID
#include <linux/user.h>
#else
#include <sys/user.h>
#endif


#include <stdarg.h>
#include <elf.h>
#include "linker.h"
#ifdef ANDROID
typedef struct pt_regs regs_t;
#else
typedef struct user_regs_struct regs_t;
#endif


/*dl function list */
struct dl_fl{
    long l_dlopen;
    long l_dlclose;
    long l_dlsym;
};


struct dyn_info{
	/**
	 * 符号表的地址
	 */
    Elf32_Addr symtab;
    /**
     * 字符串表的地址
     */
    Elf32_Addr strtab;
    /**
     * 与过程链接表单独关联的第一个重定位项的地址
     */
    Elf32_Addr jmprel;
    /**
     * 重定位项的总大小
     */
    Elf32_Word totalrelsize;
    /**
     * 重定位项的大小
     */
    Elf32_Word relsize;
    /**
     * 重定位项的数量
     */
    Elf32_Word nrels;
};


struct elf_info {
	/**
	 * 进程ID
	 */
    int pid;
    Elf32_Addr base;
    Elf32_Ehdr ehdr;
    Elf32_Phdr phdr;
    Elf32_Dyn dyn;
    Elf32_Addr dynaddr;
    /**
     * GOT表项为Elf32_Addr结构
     */
    Elf32_Word got;
    Elf32_Addr phdr_addr;
    /**
     * GOT[1] 动态库映射信息数据结构 link_map 地址
     */
    Elf32_Addr map_addr;
    Elf32_Word nchains;
};


typedef enum {
    PAT_INT,
    PAT_STR,
    PAT_MEM
}ptrace_arg_type;


typedef struct {
    ptrace_arg_type type;
    unsigned long _stackid; //private only visible in ptrace_call
    union {
        int i;
        char *s;
        struct {
            int size;
            void *addr;
        }mem;
    };
}ptrace_arg;

struct process_info {
	int pid;
	void* handle;
	unsigned long function_address;
	unsigned long function_data;
};


typedef struct dl_fl dl_fl_t;

#define pint(_x)  LOGI("[%20s( %04d )]  %-30s = %d (0x%08x)\n",__FUNCTION__,__LINE__, #_x, (int)(_x), (int)(_x))
#define puint(_x) LOGI("[%20s( %04d )]  %-30s = %u (0x%08x)\n",__FUNCTION__,__LINE__, #_x, (unsigned int)(_x), (unsigned int)(_x))
#define pstr(_x)  LOGI("[%20s( %04d )]  %-30s = %s \n",__FUNCTION__,__LINE__, #_x, (char*)(_x))

// ptrace.c
void ptrace_attach(pid_t pid);
void ptrace_cont(pid_t pid);
void ptrace_detach(pid_t pid);
void ptrace_write(pid_t pid, unsigned long addr, void *vptr, int len);
void ptrace_read(pid_t pid, unsigned long addr, void *vptr, int len);
char *ptrace_readstr(pid_t pid, unsigned long addr);
void ptrace_readreg(pid_t pid, regs_t *regs);
void ptrace_writereg(pid_t pid, regs_t *regs);
unsigned long ptrace_push(pid_t pid, regs_t *regs, void *paddr, int size);
long ptrace_stack_alloc(pid_t pid, regs_t *regs, int size);
dl_fl_t *ptrace_find_dlinfo(int pid);
void *ptrace_dlopen(pid_t pid, const char *filename, int flag);
void *ptrace_dlsym(pid_t pid, void *handle, const char *symbol);
int ptrace_dlclose(pid_t pid, void *handle);
int ptrace_mymath_add(pid_t pid, long mymath_add_addr, int a, int b) ;
void ptrace_dump_regs(regs_t *regs, char *msg) ;
int ptrace_wait_for_signal (int pid, int signal) ;
int ptrace_call(int pid, long proc, int argc, ptrace_arg *argv);

// elf.c
unsigned long get_elf_address(int pid, const char *soname);
void get_elf_info(int pid, Elf32_Addr base, struct elf_info *einfo);
void get_dyn_info(struct elf_info *einfo, struct dyn_info *dinfo);
unsigned long find_sym_in_rel(struct elf_info *einfo, const char *sym_name);
unsigned long get_function_address(int pid, const char *funcname, const char *soname);

// inject.c
int find_pid_of(const char *process_name);
int find_symbol_address(int pid, const char *function_name, const char *load_library_path);
int inject_remote_process(const char *target_process_name, const char *function_name, const char *target_so_name, const char *load_library_path);
void restore_remote_process();

/**
 * 判断该文件是否是*.so
 */
#define IS_DYN(_einfo) (_einfo->ehdr.e_type == ET_DYN)




#endif /* PTRACE_H_ */
