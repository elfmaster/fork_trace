#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <elf.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#define __BREAKPOINT__ __asm__  __volatile__("int3");
#define __RETURN_VALUE__(x) __asm__ __volatile__("mov %0, %%rax" :: "g"(x))

#ifdef DEBUG
#define DEBUG_PRINT(...) do { fprintf(stderr, __VA_ARGS__); } while(0)
#else
#define DEBUG_PRINT(...) do {} while(0)
#endif

pid_t fork_code(void) __attribute__ ((aligned(sizeof(uintptr_t))));
void fork_code_end(void);
int pid_detach(pid_t);

static void * const fork_marker_begin = fork_code;
static void * const fork_marker_end = fork_code_end;

static long retval;
/*
 * This code will get injected into a target process, and
 * spawn a fork(), which will automatically notify the tracer
 * with a SIGTRAP|PTRACE_EVENT_FORK<<8, and the tracer automatically
 * attaches to the child pid for tracing.
 */
pid_t fork_code(void)
{
	long retval;

	__asm__ volatile(
		"mov $57, %rax 	\n"
		"syscall	\n");
	/*
	 * The breakpoint is probably no longer necessary now that we are using
	 * PTRACE_O_TRACEFORK opts
	 */
	__BREAKPOINT__;

	return retval;
}

void fork_code_end(void)
{
	asm("nop");
}

int pid_read(pid_t pid, void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(uintptr_t);
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;
	long word;

	while (sz-- != 0) {
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		if (word == -1 && errno != 0) {
			fprintf(stderr, "pid_read failed: %s\n",
			    strerror(errno));
			return -1;
		}
		*(uintptr_t *)d = word;
		s += sizeof(uintptr_t);
		d += sizeof(uintptr_t);
	}
	return 0;
}

int pid_write(pid_t pid, void *dst, const void *src, size_t len)
{
	size_t rem = len % sizeof(uintptr_t);
	size_t quot = len / sizeof(uintptr_t);
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;
	
	while (quot-- != 0) {
		if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) == -1)
			goto err;
		s += sizeof(uintptr_t);
		d += sizeof(uintptr_t);
	}
	if (rem != 0) {
		long long w;
		uint8_t *wp = (uint8_t *)&w;

		w = ptrace(PTRACE_PEEKTEXT, pid, d, NULL);
		if (w == -1 && errno != 0) {
			d -= sizeof(void *) - rem;
			w = ptrace(PTRACE_PEEKTEXT, pid, d, NULL);
			if (w == -1 && errno != 0)
				goto err;
			wp += sizeof(void *) - rem;
		}
		while (rem-- != 0)
			wp[rem] = s[rem];
		if (ptrace(PTRACE_POKETEXT, pid, (void *)d, (void *)w) == -1)
			goto err;
	}
	return 0;
err:
	fprintf(stderr, "pid_write() failed: %s\n", strerror(errno));
	return -1;
}

int waitpid2(pid_t pid, int *status, int options)
{
	pid_t ret;

	do {
		ret = waitpid(pid, status, options);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

static int pid_detach_internal(pid_t pid)
{
	long ret;

	ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (ret < 0 && errno != 0) {
		fprintf(stderr, "ptrace (PTRACE_DETACH): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int
pid_attach_internal(pid_t pid)
{
	int status;
	long ret, opts;

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret < 0 && errno != 0) {
		fprintf(stderr, "ptrace (PTRACE_ATTACH): %s\n", strerror(errno));
		return -1;
	}
	do {
		if (waitpid2(pid, &status, 0) < 0)
			goto detach;
		if (!WIFSTOPPED(status))
			goto detach;
		if (WSTOPSIG(status) == SIGSTOP)
			break;
		/*
	 	 * Continue and inject signal that caused the process
		 * to stop.
		 */
		if (ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == -1)
			goto detach;
	} while(1);
	
	opts = PTRACE_O_TRACEFORK;
	ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)opts);

	return 0;
detach:
	DEBUG_PRINT("pid_attach_internal: %s\n", strerror(errno));
	(void) pid_detach_internal(pid);
	return -1;
}

static unsigned long long
get_base(pid_t pid)
{
	char path[4096];
	char buf[1024];
	FILE *fp;
	char *p;
	unsigned long long base;

	snprintf(path, sizeof(path), "/proc/%d/task/%d/maps", pid, pid);

	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "r-xp") == NULL)
			continue;
		if (strrchr(buf, '/') == NULL)
			continue;
		p = strchr(buf, '-');
		*p = '\0';
		base = strtoull(buf, NULL, 16);
		break;
	}
	return (unsigned long long)base; /* TODO */
}

/*
 * NOTE: There is an old issue where the kernel subtracts 2 from %rip due to
 * a race condition. We account for that possibility using a hack. We will find
 * a more reliable way to do this in the future.
 */
static int
call_remote_fork(pid_t pid)
{
	unsigned long long base = get_base(pid);
	size_t codesize = (char *)&fork_code_end - (char *)&fork_code;
	struct user_regs_struct pt_regs, oldregs;
	int status, i, race_condition_offset = 0;
	bool first_attempt = true;
	pid_t childpid;

	if (pid_attach_internal(pid) < 0)
		return -1;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &pt_regs) < 0)
		return -1;

	memcpy(&oldregs, &pt_regs, sizeof(pt_regs));
	if (pid_write(pid, (void *)base, (void *)&fork_code, codesize) < 0)
		return -1;
	/*
	 * Set instruction pointer to base of code segment where our
	 * shellcode is injected.
	 */
try_again:
	pt_regs.rip = base + race_condition_offset;

	DEBUG_PRINT("Setting EIP to %llx\n", pt_regs.rip);

	if (ptrace(PTRACE_SETREGS, pid, NULL, &pt_regs) < 0)
		return -1;

	/*
	 * Execute our shellcode (fork/clone)
	 */
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
		return -1;

	/*
	 * Wait for notification of fork()'d child process
	 */
	waitpid2(pid, &status, 0);
	if ((status >> 8) != (SIGTRAP | PTRACE_EVENT_FORK << 8)) {
		if (first_attempt == true && WSTOPSIG(status) == SIGSEGV) {
			memcpy(&pt_regs, &oldregs, sizeof(pt_regs));
			race_condition_offset = 2;
			first_attempt = false;
			goto try_again;
		}
		fprintf(stderr, "No PTRACE_EVENT_FORK|SIGTRAP received, signal: %d\n",
		    WSTOPSIG(status));
		return -1;
	}
	ptrace(PTRACE_GETEVENTMSG, pid, NULL, &childpid);
	DEBUG_PRINT("caught fork for child: %i\n", childpid);
	/*
	 * Restore parent process back to its original register
	 * state.
	 */
	if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs) < 0)
		return -1;
	if (ptrace(PTRACE_SETREGS, childpid, NULL, &oldregs) < 0)
		return -1;

	return childpid;
}	
	
/*
 * This is the exposed functionality which allows a user to attach
 * to a process without keeping it halted. This goes through the
 * following steps:
 * 1. Attach to process <pid>	(stops the tracee)
 * 2. Inject fork code into process text segment
 * 3. Execute fork code		(resumes the trace)
 * 3. Wait for SIGTRAP 		(stops the tracee)
 * 4. Detach from parent process (resumes the tracee)
 * 5. Attach to the child process which is in a paused via pause()
 */
pid_t
pid_attach(pid_t pid)
{
	pid_t child;

	/*
	 * Inject code that forks() a child process
	 */
	child = call_remote_fork(pid);
	if (child < 0) {
		DEBUG_PRINT("call_remote_fork failed\n");
		return -1;
	}
	if (pid_detach(pid) < 0) {
		DEBUG_PRINT("detach failed\n");
		return -1;
	}
	/*
	 * We can now do a `PTRACE_CONT` to resume tracing
	 */
	return child;
}
int
pid_detach(pid_t pid)
{

	return pid_detach_internal(pid);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	struct timespec tps, tpe;

	if (argc < 2) {
		printf("usage: %s pid\n", argv[0]);
		exit(0);
	}

	pid = atoi(argv[1]);

	clock_gettime(CLOCK_MONOTONIC_RAW, &tps);	
	if (pid_attach(pid) < 0) {
		fprintf(stderr, "Failed to attach to %d\n", pid);
		exit(EXIT_FAILURE);
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &tpe);
	printf("%lu s, %lu ns\n", tpe.tv_sec - tps.tv_sec,
	    tpe.tv_nsec - tps.tv_nsec);

	DEBUG_PRINT("Successfully attached to process\n");
	exit(EXIT_SUCCESS);
}
