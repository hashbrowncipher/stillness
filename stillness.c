#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/reg.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define ArchField offsetof(struct seccomp_data, arch)

#define BPF_Trace(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

extern long vdso_start[];
extern long vdso_end[];

struct sock_filter filter[] = {
  /* validate arch */
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),

  /* load syscall */
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

  /* list of allowed syscalls */
  BPF_Trace(clock_gettime),
  BPF_Trace(gettimeofday),
  BPF_Trace(time),
  BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
};

struct sock_fprog filterprog = {
  .len = sizeof(filter) / sizeof(filter[0]),
  .filter = filter
};


struct mapping {
  void *start;
  void *stop;
};

static inline bool endswith(const char *haystack, const char *needle) {
  int needle_len = strlen(needle);
  int haystack_len = strlen(haystack);
  if(haystack_len < needle_len) {
    return 0;
  }
  return memcmp(needle, haystack + haystack_len - needle_len - 1,
		needle_len) == 0;
}


// Adapted from
// https://github.com/eklitzke/ptrace-call-userspace
static struct mapping *find_library(pid_t pid, const char *libname) {
  char filename[32];
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE *f = fopen(filename, "r");
  char *line = NULL;
  size_t line_size = 0;
  struct mapping *ret = malloc(sizeof(struct mapping));

  while(getline(&line, &line_size, f) >= 0) {
    if(endswith(line, libname)) {
      static_assert(sizeof(void *) == sizeof(unsigned long long));
      char *stop = strchr(line, '-') + 1;
      ret->start = (void *) strtoul(line, NULL, 16);
      ret->stop = (void *) strtoul(stop, NULL, 16);
      assert(ret->start != ret->stop);
      free(line);
      fclose(f);
      return ret;
    }
  }
  free(line);
  fclose(f);
  return NULL;
}

static void *get_offset_time(struct timespec *ts, struct timespec offset) {
  clock_gettime(CLOCK_REALTIME, ts);
  ts->tv_sec += offset.tv_sec;
  ts->tv_nsec += offset.tv_nsec;
  if(ts->tv_nsec >= 1000000000) {
    ts->tv_sec += 1;
    ts->tv_nsec -= 1000000000;
  }
}

static void handle_time(pid_t pid, struct user_regs_struct regs,
			struct timespec offset) {
  time_t *time_tracee = (time_t *) regs.rdi;

  struct timespec ts;
  get_offset_time(&ts, offset);

  if(time_tracee) {
    ptrace(PTRACE_POKEDATA, pid, time_tracee, ts.tv_sec);
  }
  regs.orig_rax = -1;		// skip the syscall
  regs.rax = ts.tv_sec;		//return 0
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}



static void handle_gettimeofday(pid_t pid, struct user_regs_struct regs,
				struct timespec offset) {
  struct timeval *timeval_tracee = (struct timeval *) regs.rdi;

  regs.orig_rax = -1;		// skip the syscall
  regs.rax = 0;			//return 0
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  struct timespec ts;
  get_offset_time(&ts, offset);

  assert(ptrace(PTRACE_POKEDATA, pid, &timeval_tracee->tv_sec, ts.tv_sec) ==
	 0);
  assert(ptrace
	 (PTRACE_POKEDATA, pid, &timeval_tracee->tv_usec,
	  ts.tv_nsec / 1000) == 0);
}

static void handle_clock_gettime(pid_t pid, struct user_regs_struct regs,
				 struct timespec offset) {
  if(regs.rdi != CLOCK_REALTIME) {
    return;
  }
  struct timespec *timespec_tracee = (struct timespec *) regs.rsi;

  regs.orig_rax = -1;		// skip the syscall
  regs.rax = 0;			//return 0
  ptrace(PTRACE_SETREGS, pid, NULL, &regs);

  struct timespec ts;
  get_offset_time(&ts, offset);

  assert(ptrace(PTRACE_POKEDATA, pid, &timespec_tracee->tv_sec, ts.tv_sec)
	 == 0);
  assert(ptrace(PTRACE_POKEDATA, pid, &timespec_tracee->tv_nsec, ts.tv_nsec)
	 == 0);
}


/*
static void unmap_library(pid_t pid, const char *libname) {
        struct mapping * map = find_library(pid, libname);
        assert(map);
        fprintf(stderr, "Unmapping %s %p\n", libname, map->start);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        assert(munmap(map->start, map->stop - map->start) == 0);
        free(map);
}*/

/*
 * Taken from https://github.com/danteu/novdso
 * Licensed MIT No Attribution
 */
void inject_auxv(int pid, uintptr_t child_vdso, size_t pos) {
  int zeroCount;
  long val;

  /* skip to auxiliary vector */
  zeroCount = 0;
  while(zeroCount < 2) {
    val = ptrace(PTRACE_PEEKDATA, pid, pos += 8, NULL);
    if(val == AT_NULL)
      zeroCount++;
  }
  /* search the auxiliary vector for AT_SYSINFO_EHDR... */
  val = ptrace(PTRACE_PEEKDATA, pid, pos += 8, NULL);
  while(1) {
    if(val == AT_NULL)
      break;
    if(val == AT_SYSINFO_EHDR) {
      pos += 8;
      break;
    }

    val = ptrace(PTRACE_PEEKDATA, pid, pos += 16, NULL);
  }

  ptrace(PTRACE_POKEDATA, pid, pos, (long) child_vdso);
}

void write_vdso(pid_t pid, void *addr) {
  assert(addr != MAP_FAILED);
  assert(vdso_end - vdso_start < 0x2000);
  const int count = vdso_end - vdso_start;
  for(int i = 0; i < count; i += 1) {
    if(vdso_start[i] != 0) {
      ptrace(PTRACE_POKEDATA, pid, addr, vdso_start[i]);
    }
    addr += sizeof(long);
  }
}

struct injection_state {
  uintptr_t child_vdso;
  uintptr_t rsp;
};

struct injection_state inject_code(pid_t pid) {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &regs);

  long old_word = ptrace(PTRACE_PEEKDATA, pid, regs.rip, NULL);
  uint8_t isns[8] = {
    0x0f,
    0x05,
    0x0f,
    0x05,
    0xcc,
    0xcc,
    0xcc,
    0xcc,
  };
  long new_word;
  memmove(&new_word, isns, sizeof(new_word));
  ptrace(PTRACE_POKEDATA, pid, regs.rip, new_word);
  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);	// finish execve
  assert(waitpid(pid, NULL, 0) == pid);

  ptrace(PTRACE_SYSCALL, pid, NULL, NULL);	// start mmap
  assert(waitpid(pid, NULL, 0) == pid);
/*
    struct ptrace_syscall_info syscall_info;
    assert(ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(struct ptrace_syscall_info), &syscall_info) > 0);
    printf("%d %d\n", syscall_info.op, PTRACE_SYSCALL_INFO_EXIT);
    */

  struct user_regs_struct new_regs;
  ptrace(PTRACE_GETREGS, pid, NULL, &new_regs);

  new_regs.orig_rax = SYS_mmap;
  new_regs.rdi = 0;		// addr
  new_regs.rsi = 0x2000;	// length
  new_regs.rdx = PROT_READ | PROT_EXEC;	// prot
  new_regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;	// flags
  new_regs.r8 = -1;		// FD
  new_regs.r9 = 0;		// offset
  ptrace(PTRACE_SETREGS, pid, NULL, &new_regs);

  assert(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0);	// finish mmap
  assert(waitpid(pid, NULL, 0) == pid);
  assert(ptrace(PTRACE_GETREGS, pid, NULL, &new_regs) == 0);
  write_vdso(pid, (void *) new_regs.rax);

  // restore the original state of the program
  assert(ptrace(PTRACE_POKEDATA, pid, regs.rip, old_word) == 0);
  assert(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == 0);
  return (struct injection_state) {
    .child_vdso = new_regs.rax,.rsp = regs.rsp
  };
}



int handle_ptrace_event(int status, pid_t pid, struct timespec offset) {
  switch (status) {
  case PTRACE_EVENT_VFORK:
  case PTRACE_EVENT_FORK:
    pid_t new_pid;
    ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid);
    assert(waitpid(new_pid, NULL, 0) == new_pid);
    ptrace(PTRACE_CONT, new_pid, NULL, 0);
    break;
  case PTRACE_EVENT_EXEC:
    struct injection_state state = inject_code(pid);
    inject_auxv(pid, state.child_vdso, state.rsp);
    break;
  case PTRACE_EVENT_SECCOMP:
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    int syscall_no = regs.orig_rax;

    switch (regs.orig_rax) {
    case SYS_clock_gettime:
      handle_clock_gettime(pid, regs, offset);
      break;
    case SYS_gettimeofday:
      handle_gettimeofday(pid, regs, offset);
      break;
    case SYS_time:
      handle_time(pid, regs, offset);
      break;
    default:
      fprintf(stderr, "Unkown syscall: %d\n", syscall_no);
      abort();
      break;
    }
    break;
  }
}

struct timespec make_offset(long target) {
  struct timespec ret;
  clock_gettime(CLOCK_REALTIME, &ret);

  ret.tv_sec = target - ret.tv_sec;
  if(ret.tv_nsec > 0) {
    ret.tv_sec -= 1;		// borrow
    ret.tv_nsec = 1000000000 - ret.tv_nsec;
  }

  return ret;
}

int trace_process(int main_pid, long start_time) {
  int status;

  wait(&status);
  assert(ptrace(PTRACE_SETOPTIONS,
		main_pid,
		0,
		PTRACE_O_EXITKILL |
		PTRACE_O_TRACESYSGOOD |
		PTRACE_O_TRACEEXEC |
		PTRACE_O_TRACEFORK |
		PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP) == 0);
  assert(ptrace(PTRACE_CONT, main_pid, NULL, NULL) == 0);
  struct timespec offset = make_offset(start_time);

  pid_t pid;
  while((pid = wait(&status)) != -1) {
    if(WIFEXITED(status) || WIFSIGNALED(status)) {
      if(pid == main_pid) {
	break;
      }
      continue;
    }

    int signal = WSTOPSIG(status);
    if(((status >> 8) & 0x7f) == SIGTRAP) {
      signal = 0;
      handle_ptrace_event(status >> 16, pid, offset);
    }

    ptrace(PTRACE_CONT, pid, NULL, signal);
  }
  if(WIFSIGNALED(status)) {
    // TODO: this means that if they core dump, so do we.
    // How to fix?
    kill(0, WTERMSIG(status));
  }
  return WEXITSTATUS(status);
}

int run_child(char *command, char **argv) {
  if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("Could not start seccomp:");
    exit(1);
  }
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
    perror("Could not start seccomp:");
    exit(1);
  }

  assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
  kill(getpid(), SIGSTOP);
  execvp(command, argv);
  perror("Failed to exec child process: ");
  return 1;
}

int main(int argc, char *argv[]) {
  if(argc < 3) {
    fprintf(stderr, "usage: %s <unix timestamp> <command>\n", argv[0]);
    return 1;
  }

  char *endptr;
  long start_time = strtol(argv[1], &endptr, 10);
  if(endptr[0] != 0 || errno != 0) {
    fprintf(stderr, "invalid start time: %s\n", argv[1]);
    return 1;
  }

  pid_t child = fork();
  if(child == 0) {
    return run_child(argv[2], &argv[2]);
  }

  return trace_process(child, start_time);

}
