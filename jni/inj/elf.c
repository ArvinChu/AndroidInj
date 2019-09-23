/*
 * elf.c
 *
 *  Created on: Jun 4, 2011
 *      Author: d
 */

#include <stdlib.h>
#include <stdio.h>
#include "utils.h"

#ifdef ANDROID
//#include <linker.h>
#else
#include <link.h>
#include <elf.h>
#endif

// typedef __uint32_t	Elf32_Addr;	/* Unsigned program address */
/**
 * 获取 ELF 文件信息
 * @param pid : 目标进程
 * @param base : ELF 文件起始地址
 * @param einfo : 需要写入的 ELF 信息
 */
void get_elf_info(int pid, Elf32_Addr base, struct elf_info *einfo) {
    int i = 0;

    einfo->pid = pid;
    einfo->base = base;
//    /* ELF Header */
//    typedef struct elfhdr {
//    	unsigned char	e_ident[EI_NIDENT]; /* ELF Identification */
//    	Elf32_Half	e_type;		/* object file type */
//    	Elf32_Half	e_machine;	/* machine */
//    	Elf32_Word	e_version;	/* object file version */
//    	Elf32_Addr	e_entry;	/* virtual entry point */
//    	Elf32_Off	e_phoff;	/* program header table offset */
//    	Elf32_Off	e_shoff;	/* section header table offset */
//    	Elf32_Word	e_flags;	/* processor-specific flags */
//    	Elf32_Half	e_ehsize;	/* ELF header size */
//    	Elf32_Half	e_phentsize;	/* program header entry size */
//    	Elf32_Half	e_phnum;	/* number of program header entries */
//    	Elf32_Half	e_shentsize;	/* section header entry size */
//    	Elf32_Half	e_shnum;	/* number of section header entries */
//    	Elf32_Half	e_shstrndx;	/* section header table's "section
//    					   header string table" entry offset */
//    } Elf32_Ehdr;
    // 读取ELF文件头
    ptrace_read(pid, einfo->base, &einfo->ehdr, sizeof(Elf32_Ehdr));
    // 计算程序头表起始地址
    einfo->phdr_addr = einfo->base + einfo->ehdr.e_phoff;
    puint(einfo->phdr_addr);
    // 文件类型: *.a *.o *.so bin等等
    puint(einfo->ehdr.e_type);
//    /* Program Header */
//    typedef struct {
//    	Elf32_Word	p_type;		/* segment type */
//    	Elf32_Off	p_offset;	/* segment offset */
//    	Elf32_Addr	p_vaddr;	/* virtual address of segment */
//    	Elf32_Addr	p_paddr;	/* physical address - ignored? */
//    	Elf32_Word	p_filesz;	/* number of bytes in file for seg. */
//    	Elf32_Word	p_memsz;	/* number of bytes in mem. for seg. */
//    	Elf32_Word	p_flags;	/* flags */
//    	Elf32_Word	p_align;	/* memory alignment */
//    } Elf32_Phdr;
    // 读取程序头表第1项
    ptrace_read(pid, einfo->phdr_addr, &einfo->phdr, sizeof(Elf32_Phdr));
    // 打印程序头表中有多少个项
    LOGI("dump %d phdr\n", einfo->ehdr.e_phnum);
    // 读取所有程序头
    for(i=0; i < einfo->ehdr.e_phnum; i++) {
        Elf32_Phdr phdr;
        ptrace_read(pid, einfo->phdr_addr + i * sizeof(Elf32_Phdr), &phdr, sizeof(Elf32_Phdr));
    }
    // 该Segment是否是.dynamic，这个段里保存了动态链接器所需要的基本信息
    while (einfo->phdr.p_type != PT_DYNAMIC) {
        ptrace_read(pid, einfo->phdr_addr += sizeof(Elf32_Phdr), &einfo->phdr, sizeof(Elf32_Phdr));
    }
    // 该Segment的第1个字节在内存中的虚拟地址，包含Elf32_Dyn结构的数组的Segment
    einfo->dynaddr =  (IS_DYN(einfo) ? einfo->base : 0) + einfo->phdr.p_vaddr;
    pint(einfo->dynaddr);
//    /* Dynamic structure */
//    typedef struct {
//    	Elf32_Sword	d_tag;		/* controls meaning of d_val */
//    	union {
//    		Elf32_Word	d_val;	/* Multiple meanings - see d_tag */
//    		Elf32_Addr	d_ptr;	/* program virtual address */
//    	} d_un;
//    } Elf32_Dyn;
    ptrace_read(pid, einfo->dynaddr, &einfo->dyn, sizeof(Elf32_Dyn));
    // DT_PLTGOT: 与过程链接表或全局偏移表关联的地址
    while (einfo->dyn.d_tag != DT_PLTGOT) {
        ptrace_read(pid, einfo->dynaddr + i * sizeof(Elf32_Dyn), &einfo->dyn, sizeof(Elf32_Dyn));
        i++;
    }
    // 计算GOT在内存中的虚拟地址
    einfo->got = (IS_DYN(einfo) ? einfo->base : 0) + (Elf32_Word) einfo->dyn.d_un.d_ptr;
    pint(einfo->got);
    // map_addr的意义未明确
    ptrace_read(pid, einfo->got + 4, &einfo->map_addr, 4);
    pint(einfo->map_addr);
}

/**
 * 遍历重定位表查找符号（函数名）的重定位地址
 * 重定位：函数调用过程中, 动态链接器会把函数名与函数实际所在的地址(即符号定义)联系到一起
 */
unsigned long find_sym_in_rel(struct elf_info *einfo, char *sym_name) {
    Elf32_Rel rel;
    Elf32_Sym sym;
    unsigned int i;
    char *str = NULL;
    unsigned long ret;
    struct dyn_info dinfo;
    LOGI("find sym in rel %p %s \n", (void*)einfo->base, sym_name);

    get_dyn_info(einfo, &dinfo);
    pint(dinfo.nrels);
    pint(dinfo.jmprel);
    pint(dinfo.relsize);
    pint(dinfo.totalrelsize);
    for (i = 0; i < dinfo.nrels; i++) {
        ptrace_read(einfo->pid, (unsigned long) (dinfo.jmprel + i * sizeof(Elf32_Rel)), &rel, sizeof(Elf32_Rel));
        LOGI("rel addr %p\n", &rel);

        // ELF32_R_SYM 表示重定位类型特定于处理器
        if (ELF32_R_SYM(rel.r_info)) {
        	// r_info 指定必须对其进行重定位的符号表索引以及要应用的重定位类型
            ptrace_read(einfo->pid, dinfo.symtab + ELF32_R_SYM(rel.r_info) * sizeof(Elf32_Sym), &sym, sizeof(Elf32_Sym));
//            /* Symbol Table Entry */
//            typedef struct elf32_sym {
//            	Elf32_Word	st_name;	/* name - index into string table */
//            	Elf32_Addr	st_value;	/* symbol value */
//            	Elf32_Word	st_size;	/* symbol size */
//            	unsigned char	st_info;	/* type and binding */
//            	unsigned char	st_other;	/* 0 - no defined meaning */
//            	Elf32_Half	st_shndx;	/* section header index */
//            } Elf32_Sym;
            // st_name 表示符号名称的字符串表的索引；若其值为 0 则代表临时寄存器。
            // 字符串表中的各字符串均以'\0'结尾
            str = ptrace_readstr(einfo->pid, dinfo.strtab + sym.st_name);
            LOGI("   str-> %s\n", str);
            // str在ptrace_readstr函数中malloc，所以要在下面free
            // 如果读取的字符串等于sym_name，则找到sym_name函数
            if (strcmp(str, sym_name) == 0) {
                free(str);
                break;
            }
            free(str);
        }
    }

    if (i == dinfo.nrels) {
    	// 未找到
        ret = 0;
    } else {
    	ret = (IS_DYN(einfo) ? einfo->base : 0) + rel.r_offset;
    }
    pint(ret);
    return ret;
}

/**
 * 在进程自身的映象中（即不包括动态共享库，无须遍历link_map链表）获得各种动态信息
 */
void get_dyn_info(struct elf_info *einfo, struct dyn_info *dinfo) {
    Elf32_Dyn dyn;
    int i = 0;

    LOGI("get_dyn_info 0x%08x...\n", einfo->dynaddr);

    // 包含Elf32_Dyn结构的数组的节
    ptrace_read(einfo->pid, einfo->dynaddr + i * sizeof(Elf32_Dyn), &dyn, sizeof(Elf32_Dyn));
    i++;
    // DT_NULL定义为0，标记 _DYNAMIC 数组的结尾
    while (dyn.d_tag) {
        switch (dyn.d_tag) {
        case DT_SYMTAB: // 符号表的地址
        	LOGI("DT_SYMTAB");
            dinfo->symtab = (IS_DYN(einfo) ? einfo->base : 0) + dyn.d_un.d_ptr;
            break;
        case DT_STRTAB: // 字符串表的地址
        	LOGI("DT_STRTAB");
            dinfo->strtab = (IS_DYN(einfo) ? einfo->base : 0) + dyn.d_un.d_ptr;
            break;
        case DT_JMPREL: // 与过程链接表单独关联的第一个重定位项的地址
        	LOGI("DT_JMPREL");
            dinfo->jmprel = (IS_DYN(einfo) ? einfo->base : 0) + dyn.d_un.d_ptr;
            break;
        case DT_PLTRELSZ: // 与过程链接表关联的重定位项的总大小
        	LOGI("DT_PLTRELSZ");
            dinfo->totalrelsize = dyn.d_un.d_val;
            break;
        case DT_RELAENT: // DT_RELA 重定位项的大小
        	LOGI("DT_RELAENT");
            dinfo->relsize = dyn.d_un.d_val;
            break;
        case DT_RELENT: // DT_REL 重定位项的大小
        	LOGI("DT_RELENT");
            dinfo->relsize = dyn.d_un.d_val;
            break;
        }
        ptrace_read(einfo->pid, einfo->dynaddr + i * sizeof(Elf32_Dyn), &dyn, sizeof(Elf32_Dyn));
        i++;
    }

    if (dinfo->relsize == 0) {
//    	/* Relocation entry with implicit addend */
//    	typedef struct {
//    		Elf32_Addr	r_offset;	/* offset of relocation */
//    		Elf32_Word	r_info;		/* symbol table index and type */
//    	} Elf32_Rel;
    	// 重定位项结构如上, 大小为8个字节
        dinfo->relsize = 8;
    }
    // 重定位项的数量
    dinfo->nrels = dinfo->totalrelsize / dinfo->relsize;
}

long replace_all_rels(int pid, char *funcname, long addr, char **sos) {
    FILE *m = NULL;
    unsigned int i = 0;
    char maps[80];
    char line[200];
    char soaddrs[20];
    char soaddr[10];
    char soname[60];
    char prop[10];
    long soaddval;
    long base, function_addr;
    memset(maps, 0, sizeof(maps));
    memset(soaddrs, 0, sizeof(soaddrs));
    memset(soaddr, 0, sizeof(soaddr));
    sprintf(maps, "/proc/%d/maps", pid);
    m = fopen(maps, "r");
    if(!m) {
    	LOGE("open %s error!\n", maps);
    }
    // 读取文件的每一行
    while(fgets(line, sizeof(line), m)) {
        int in_so_list = 0;
        struct elf_info einfo;
        long tmpaddr = 0;
        // 如果以
        // if(strstr(line,".so") == NULL && i != 0) continue;
        if(strstr(line,"r-xp") == NULL) continue;

        for(i = 0; sos[i] != NULL; i++) {
            if(strstr(line, sos[i]) != NULL) {
                in_so_list = 1;
                break;
            }
        }
        if(!in_so_list) {
            continue;
        }
        // 解析每一行内容（*是略过该字符串），获取ELF文件起始地址，属性，文件名
        sscanf(line, "%s %s %*s %*s %*s %s", soaddrs, prop, soname);
        // 获取起始地址（[^-]是读到‘-’为止）
        sscanf(soaddrs, "%[^-]", soaddr);
        LOGI("#### %s %s %s\n", soaddr, prop, soname);
        // 表示转为16进制unsigned long类型
        base = strtoul(soaddr, NULL, 16);
        puint(base);
        get_elf_info(pid, base, &einfo);
        tmpaddr = find_sym_in_rel(&einfo, funcname);
        if(tmpaddr != 0) {
        	ptrace_read(pid, tmpaddr, &function_addr, 4);
        	LOGI("base of %08x\n", (int)function_addr);
            ptrace_write(pid, tmpaddr, &addr, 4);
            LOGI("base of %-40s     %08x  %08x %08x\n", soname, (int)base, (int)tmpaddr, (int)addr);
            return function_addr;
        }
    }
}



