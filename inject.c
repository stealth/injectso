/*
 * Copyright (C) 2007-2025 Sebastian Krahmer
 * All rights reserved.
 *
 * This is NOT a common BSD license, so read on.
 *
 * Redistribution in source and use in binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. The provided software is FOR EDUCATIONAL PURPOSES ONLY! You must not
 *    use this software or parts of it to commit crime or any illegal
 *    activities. Local law may forbid usage or redistribution of this
 *    software in your country.
 * 2. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 3. Redistribution in binary form is not allowed.
 * 4. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 5. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <dlfcn.h>


#ifdef ANDROID
typedef struct {
	uint32_t a_type;
	union {
		uint32_t a_val;
	} a_un;
} Elf32_auxv_t;

#endif

#ifdef __x86_64__
#define elf_auxv_t Elf64_auxv_t
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#else
#define elf_auxv_t Elf32_auxv_t
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#endif

#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif


struct process_hook {
	const char *symbol;
	pid_t pid;
	char *dso;
	void *dlopen_address;
	uint32_t flags;
} process_hook = {NULL, 0, NULL, NULL, 0};

enum {
	PROCESS_NOFLAG = 0,
	PROCESS_NOPRELINK = 1
};

void die(const char *s)
{
	perror(s);
	exit(errno);
}


void show_auxv(const char *pid)
{
	char buf[1024];
	int fd = -1;
	ssize_t r = 0;
	elf_auxv_t *auxv = NULL;

	snprintf(buf, sizeof(buf), "/proc/%s/auxv", pid);

	if ((fd = open(buf, O_RDONLY)) < 0)
		die("[-] open");

	if ((r = read(fd, buf, sizeof(buf))) < 0)
		die("[-] read");
	close(fd);

	for (auxv = (elf_auxv_t *)buf; auxv->a_type != AT_NULL && (char *)auxv < buf + r; ++auxv) {
		switch (auxv->a_type) {
		case AT_IGNORE:
			printf("AT_IGNORE\n");
			break;
		case AT_EXECFD:
			printf("AT_EXECFD:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PHDR:
			printf("AT_PHDR:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_PHENT:
			printf("AT_PHENT:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PHNUM:
			printf("AT_PHNUM:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PAGESZ:
			printf("AT_PAGESZ:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_BASE:
			printf("AT_BASE:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_FLAGS:
			printf("AT_FLAGS:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_ENTRY:
			printf("AT_ENTRY:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_UID:
			printf("AT_UID:\t\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_EUID:
			printf("AT_EUID:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_GID:
			printf("AT_GID:\t\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_EGID:
			printf("AT_EGID:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_CLKTCK:
			printf("AT_CLKTCK:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PLATFORM:
			printf("AT_PLATFORM:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_HWCAP:
			printf("AT_HWCAP:\t0x%zx\n", auxv->a_un.a_val);
			break;
#ifndef ANDROID
		case AT_FPUCW:
			printf("AT_FPUCW:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_DCACHEBSIZE:
			printf("AT_DCACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_ICACHEBSIZE:
			printf("AT_ICACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_UCACHEBSIZE:
			printf("AT_UCACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_SYSINFO:
			printf("AT_SYSINFO:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_SYSINFO_EHDR:
			printf("AT_SYSINFO_EHDR:%p\n", (void *)auxv->a_un.a_val);
			break;
#endif
		case AT_SECURE:
			printf("AT_SECURE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_RANDOM:
			printf("AT_RANDOM:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_EXECFN:
			printf("AT_EXECFN:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		default:
			printf("AT_UNKNOWN(%zd):\t0x%zx\n", auxv->a_type, auxv->a_un.a_val);
		}
	}
}


size_t at_base(pid_t pid)
{
	char buf[1024];
	int fd = -1;
	ssize_t r = 0;
	elf_auxv_t *auxv = NULL;

	snprintf(buf, sizeof(buf), "/proc/%d/auxv", pid);

	if ((fd = open(buf, O_RDONLY)) < 0)
		die("[-] open");

	if ((r = read(fd, buf, sizeof(buf))) < 0)
		die("[-] read");
	close(fd);

	for (auxv = (elf_auxv_t *)buf; auxv->a_type != AT_NULL && (char *)auxv < buf + r; ++auxv) {
		if (auxv->a_type == AT_BASE)
			return auxv->a_un.a_val;
	}
	return 0;
}


char *find_libc_start(pid_t pid)
{
	char path[1024];
	char buf[1024], *start = NULL, *p = NULL, *addr1 = NULL;
	FILE *f = NULL;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	if ((f = fopen(path, "r")) == NULL)
		die("[-] fopen");

	for (;;) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (!strstr(buf, "r-xp"))
			continue;
		if (!(p = strstr(buf, "/")))
			continue;
		if (!strstr(p, "/lib64/libc-") && !strstr(p, "/lib/libc-") && !strstr(p, "/lib/x86_64-linux-gnu/libc-") &&
		    !strstr(p, "/lib/libc.so"))	/* Android */
			continue;
		start = strtok(buf, "-");
		addr1 = (char *)strtoul(start, NULL, 16);
		break;
	}

	fclose(f);
	return addr1;
}


int poke_text(pid_t pid, size_t addr, void *buf, size_t blen)
{
	int i = 0;
	size_t alen = blen + sizeof(size_t) - (blen % sizeof(size_t)); /* word align */
	char *ptr = NULL;

	if ((ptr = (char *)malloc(alen)) == NULL)
		die("[-] malloc");

	memset(ptr, 0, alen);
	memcpy(ptr, buf, blen);

	for (i = 0; i < blen; i += sizeof(size_t)) {
		if (ptrace(PTRACE_POKETEXT, pid, (void *)(addr + i), (void *)*(size_t *)&ptr[i]) < 0)
			die("[-] ptrace POKE");
	}
	free(ptr);
	return 0;
}


int peek_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	size_t word = 0;
	for (i = 0; i < blen; i += sizeof(size_t)) {
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + i), NULL);
		memcpy(&buf[i], &word, sizeof(word));
	}
	return 0;
}


/* Prelinked ELF's, such as in Fedora, have non-zero v_addr's.
 * returns 0 if not prelinked, -1 if invalid/nonexisting, > 0 if prelinked
 */
int is_prelinked(const struct process_hook *ph, const char *path)
{
	Elf_Ehdr ehdr;
	Elf_Phdr phdr;
	int fd = -1, i = 0, found = 0;

	if (ph->flags & PROCESS_NOPRELINK)
		return 0;

	if ((fd = open(path, O_RDONLY)) < 0)
		return -1;

	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		close(fd);
		return -1;
	}

	if (memcmp(ehdr.e_ident, "\177ELF",  4) != 0) {
		close(fd);
		return 0;
	}

	if (lseek(fd, ehdr.e_phoff, SEEK_SET) != ehdr.e_phoff) {
		close(fd);
		return -1;
	}

	for (i = 0; i < ehdr.e_phnum; ++i) {
		if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) {
			close(fd);
			return -1;
		}
		if (phdr.p_type == PT_LOAD) {
			found = 1;
			break;
		}
	}

	close(fd);

	if (!found)
		return 0;

	return phdr.p_vaddr != 0;
}


#ifdef __x86_64__
/* from linux/user.h which disappeared recently: */
struct my_user_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
/* end of arguments */
/* cpu exception frame or undefined */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};


int inject_code(const struct process_hook *ph)
{
	char sbuf1[1024], sbuf2[1024];
	struct my_user_regs regs, saved_regs, aregs;
	int status = 0;
	size_t v = 0;

	assert(ph);

	printf("[*] x86_64 mode\n");

	if (ptrace(PTRACE_ATTACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace ATTACH");
	waitpid(ph->pid, &status, 0);
	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace GETREGS");

	peek_text(ph->pid, regs.rsp + 1024, sbuf1, sizeof(sbuf1));
	peek_text(ph->pid, regs.rsp, sbuf2, sizeof(sbuf2));

	/* fake saved return address, triggering a SIGSEGV to catch */
	v = 0;
	poke_text(ph->pid, regs.rsp, (char *)&v, sizeof(v));
	poke_text(ph->pid, regs.rsp + 1024, ph->dso, strlen(ph->dso) + 1);

	memcpy(&saved_regs, &regs, sizeof(regs));
	printf("[+] rdi=0x%lx rsp=0x%lx rip=0x%lx\n", regs.rdi, regs.rsp, regs.rip);

	/* arguments to function we call */
	regs.rdi = regs.rsp + 1024;
	regs.rsi = RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE;
	regs.rip = (size_t)ph->dlopen_address + 2;// kernel bug?! always need to add 2!

	if (ptrace(PTRACE_SETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace SETREGS");

	do {
		if (ptrace(PTRACE_CONT, ph->pid, NULL, NULL) < 0)
			die("[-] ptrace CONT");
		/* Should receive a SIGSEGV for return to 0 */
		waitpid(ph->pid, &status, 0);
	} while (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV));

	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &aregs) < 0)
		die("[-] ptrace GETREGS");

	printf("[+] rdi=0x%lx rsp=0x%lx rip=0x%lx\n", aregs.rdi, aregs.rsp, aregs.rip);
	if (ptrace(PTRACE_SETREGS, ph->pid, 0, &saved_regs) < 0)
		die("[-] ptrace SETREGS");

	poke_text(ph->pid, saved_regs.rsp + 1024, sbuf1, sizeof(sbuf1));
	poke_text(ph->pid, saved_regs.rsp, sbuf2, sizeof(sbuf2));

	if (ptrace(PTRACE_DETACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace DETACH");
	if (aregs.rip != 0)
		printf("[-] dlopen in target may have failed (no clean NULL fault)\n");

	return 0;
}

#elif defined ARM

struct my_user_regs {
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
	unsigned long r4;
	unsigned long r5;
	unsigned long r6;
	unsigned long r7;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long fp;
	unsigned long ip;
	unsigned long sp;
	unsigned long lr;
	unsigned long pc;
	unsigned long cpsr;
	unsigned long ORIG_r0;
};


int inject_code(const struct process_hook *ph)
{
	char sbuf1[256]; /* made this smaller, sample programs didn't have much stack avail */
	struct my_user_regs regs, saved_regs, aregs;
	int status = 0;

	assert(ph);

#ifdef THUMB
	printf("[*] ARM Thumb mode\n");
#else
	printf("[*] ARM mode\n");
#endif

	if (ptrace(PTRACE_ATTACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace ATTACH");
	waitpid(ph->pid, &status, 0);
	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace GETREGS");

	memcpy(&saved_regs, &regs, sizeof(regs));

#ifdef THUMB
	regs.cpsr |= (1<<5);	/* re-enable processing of Thumb opcodes */

	/* fake saved return address, triggering a SIGSEGV to catch */
	regs.lr = 0x00000001;
#else
	regs.lr = 0x00000000;
#endif

	peek_text(ph->pid, regs.sp, sbuf1, sizeof(sbuf1));

	/* write out dso filename on stack */
	poke_text(ph->pid, (regs.sp + 64) & 0xfffffffc, ph->dso, strlen(ph->dso) + 1);

	printf("[+] r0=0x%lx sp=0x%lx pc=0x%lx\n", regs.r0, regs.sp, regs.pc);

	/* arguments to function we call */
	regs.r0 = (regs.sp + 64) & 0xfffffffc;
	regs.r1 = RTLD_NOW|RTLD_GLOBAL;

#ifndef ANDROID
	regs.r1 |= RTLD_NODELETE;
#endif
	regs.pc = (uint32_t)(ph->dlopen_address);

	printf("[*] PC alignment: 0x%lx\n", regs.pc);

	if (ptrace(PTRACE_SETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace SETREGS");

	do {
		if (ptrace(PTRACE_CONT, ph->pid, NULL, NULL) < 0)
			die("[-] ptrace CONT");
		/* Should receive a SIGSEGV for return to 0 */
		waitpid(ph->pid, &status, 0);
	} while (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV));


	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &aregs) < 0)
		die("[-] ptrace GETREGS");

	printf("[+] r0=0x%lx sp=0x%lx pc=0x%lx cpsr=0x%lx\n", aregs.r0, aregs.sp, aregs.pc, aregs.cpsr);

	poke_text(ph->pid, saved_regs.sp, sbuf1, sizeof(sbuf1));

	if (ptrace(PTRACE_SETREGS, ph->pid, 0, &saved_regs) < 0)
		die("[-] ptrace SETREGS");
	if (ptrace(PTRACE_DETACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace DETACH");
	if (aregs.pc != 0)
		printf("[-] dlopen in target may have failed (no clean NULL fault)\n");

	return 0;
}

#else // x86

struct my_user_regs {
	uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
	unsigned short ds, __ds, es, __es;
	unsigned short fs, __fs, gs, __gs;
	uint32_t orig_eax, eip;
	unsigned short cs, __cs;
	uint32_t eflags, esp;
	unsigned short ss, __ss;
};


int inject_code(const struct process_hook *ph)
{
	char sbuf1[1024], sbuf2[1024];
	struct my_user_regs regs, saved_regs, aregs;
	int status = 0;
	size_t v = 0;

	assert(ph);

	printf("[*] x86 mode\n");

	if (ptrace(PTRACE_ATTACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace ATTACH");
	waitpid(ph->pid, &status, 0);
	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace GETREGS");

	peek_text(ph->pid, regs.esp + 1024, sbuf1, sizeof(sbuf1));
	peek_text(ph->pid, regs.esp, sbuf2, sizeof(sbuf2));

	/* fake saved return address, triggering a SIGSEGV to catch */
	v = 0x0;
	poke_text(ph->pid, regs.esp, (char *)&v, sizeof(v));
	poke_text(ph->pid, regs.esp + 1024, ph->dso, strlen(ph->dso) + 1); 

	memcpy(&saved_regs, &regs, sizeof(regs));

	printf("[+] esp=0x%lx eip=0x%lx\n", regs.esp, regs.eip);

	/* arguments passed on stack this time (x86) */
	v = regs.esp + 1024;
	poke_text(ph->pid, regs.esp + sizeof(size_t), &v, sizeof(v));
	v = RTLD_NOW|RTLD_GLOBAL;
#ifndef ANDROID
	v |= RTLD_NODELETE;
#endif
	poke_text(ph->pid, regs.esp + 2*sizeof(size_t), &v, sizeof(v));

	/* kernel bug. always add 2; in -m32 mode on 64bit systems its
	 * not needed!!!
	 */
	regs.eip = (size_t)ph->dlopen_address + 2;
	//regs.eip = (size_t)ph->dlopen_address;

	if (ptrace(PTRACE_SETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace SETREGS");
	do {
		if (ptrace(PTRACE_CONT, ph->pid, NULL, NULL) < 0)
			die("[-] ptrace CONT");
		/* Should receive a SIGSEGV for return to 0 */
		waitpid(ph->pid, &status, 0);
	} while (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV));

	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &aregs) < 0)
		die("[-] ptrace GETREGS");

	printf("[+] esp=0x%lx eip=0x%lx\n", aregs.esp, aregs.eip);

	if (ptrace(PTRACE_SETREGS, ph->pid, 0, &saved_regs) < 0)
		die("[-] ptrace SETREGS");

	poke_text(ph->pid, saved_regs.esp + 1024, sbuf1, sizeof(sbuf1));
	poke_text(ph->pid, saved_regs.esp, sbuf2, sizeof(sbuf2));

	if (ptrace(PTRACE_DETACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace DETACH");
	if (aregs.eip != 0)
		printf("[-] dlopen in target may have failed (no clean NULL fault)\n");

	return 0;
}

#endif

void usage(const char *path)
{
	printf("Usage: %s <-p pid> <-P dso-path> [-s pid]\n", path);
	exit(1);
}


/* The easy way to calculate address of target symbol
 */
void fill_offsets_maps(struct process_hook *ph)
{
	char *my_libc = NULL, *daemon_libc = NULL;
	int32_t dlopen_offset = 0;
	char *dlopen_mode = NULL;

	assert(ph);

	printf("[*] Using /proc/pid/maps method ...\n");
	my_libc = find_libc_start(getpid());
	if (!my_libc) {
		printf("[-] Unable to locate my own libc.\n");
		return;
	}

	dlopen_mode = dlsym(RTLD_DEFAULT, ph->symbol);
	if (dlopen_mode)
		printf("[+] My '%s': %p\n", ph->symbol, dlopen_mode);
	else {
		printf("[-] Unable to locate my own '%s' address.\n", ph->symbol);
		return;
	}

	dlopen_offset = dlopen_mode - my_libc;
	daemon_libc = find_libc_start(ph->pid);
	if (!daemon_libc) {
		printf("[-] Unable to locate target's libc.\n");
		return;
	}
	printf("[+] Foreign libc start: %p, offset=%d\n", daemon_libc, dlopen_offset);
	ph->dlopen_address = daemon_libc + dlopen_offset;
}


/* The last chance if nothing above worked */
void fill_offsets_nm(struct process_hook *ph)
{
	FILE *pfd = NULL;
	char buf[128], *space = NULL, *daemon_libc = NULL, *my_libc = NULL;
	size_t dlopen_offset = 0;
	int prelinked = 0;

	assert(ph);

	printf("[*] Using nm method ...\n");
	daemon_libc = find_libc_start(ph->pid);
	if (!daemon_libc) {
		printf("[-] Unable to locate foreign libc.\n");
		return;
	}

	my_libc = find_libc_start(getpid());
	if (!my_libc) {
		printf("[-] Unable to locate my own libc.\n");
		return;
	}

	memset(buf, 0, sizeof(buf));

	char *libcs[] = {"/lib64/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6", "/lib/libc.so.6",  NULL};

	for (int i = 0; libcs[i]; ++i) {

		printf("[*] Trying `%s` ...\n", libcs[i]);
		if (access(libcs[i], R_OK) != 0) {
			printf("[-] Failed.\n");
			continue;
		}
		printf("[+] Success.\n");

		prelinked = is_prelinked(ph, libcs[i]);

		if (prelinked != -1) {
			char cmd[64] = {0};
			snprintf(cmd, sizeof(cmd), "nm %s 2>/dev/null|grep __libc_dlopen_mode", libcs[i]);
			pfd = popen(cmd, "r");
		}

		if (pfd) {
			if (prelinked > 0)
				printf("[*] found prelinked libc\n");
			else
				printf("[*] libc not prelinked\n");

			for (;!feof(pfd);) {
				memset(buf, 0, sizeof(buf));
				if (!fgets(buf, sizeof(buf), pfd))
					break;
				if (strstr(buf, " T "))
					break;
			}
			if ((space = strchr(buf, ' ')) != NULL)
				*space = 0;
			dlopen_offset = strtoul(buf, NULL, 16);
			fclose(pfd);
		}
		if (dlopen_offset)
			break;
	}

	if (!dlopen_offset) {
		printf("[-] Unable to locate symbol via nm.\n");
		return;
	}

	/* In prelinking, the 'offset' is already the absolute address,
	 * so subtract the base. This is needed as daemon's base can still
	*  be different, even when using prelinked libs (sshd)
	 */
	if (prelinked > 0)
		dlopen_offset -= (size_t)my_libc;

	ph->dlopen_address = daemon_libc + dlopen_offset;
}


int main(int argc, char **argv)
{
	int c;
	char pbuf[PATH_MAX];

	while ((c = getopt(argc, argv, "s:p:P:")) != -1) {
		switch (c) {
		case 'P':
#ifdef ANDROID
			process_hook.dso = strdup(optarg);
#else
			process_hook.dso = realpath(optarg, pbuf);
#endif
			break;
		case 'p':
			process_hook.pid = atoi(optarg);
			break;
		case 's':
			show_auxv(optarg);
			exit(0);
		default:
			usage(argv[0]);
		}
	}

#ifdef ANDROID
	process_hook.symbol = "dlopen";
#else
	setbuffer(stdout, NULL, 0);
	process_hook.symbol = "__libc_dlopen_mode";
#endif

	printf("injectso v0.53 -- DSO process hotpatching tool\n\n");
	if (!process_hook.dso || !process_hook.pid) {
		usage(argv[0]);
	}

	if (access(process_hook.dso, R_OK|X_OK) < 0) {
		fprintf(stderr, "[-] DSO is not rx\n");
		return 1;
	}

	fill_offsets_maps(&process_hook);

/* Both methods only work on a common Linux box */
#ifndef ANDROID

	if (process_hook.dlopen_address == 0) {
		fill_offsets_nm(&process_hook);
	}
#endif

	if (process_hook.dlopen_address == 0) {
		printf("[-] Unable to locate foreign dlopen address.\n");
		return 1;
	}

	printf("[+] => Foreign '%s' address: %p\n", process_hook.symbol, process_hook.dlopen_address);
	printf("[*] Using normalized DSO path '%s'\n", process_hook.dso);
	inject_code(&process_hook);

	printf("[+] done.\n");

	return 0;
}

