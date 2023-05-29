#include <time.h>

int __vdso_clock_gettime(clockid_t clock, struct timespec *ts) {
  ts->tv_sec = 0;
  ts->tv_nsec = 0;
  return 0;
}

int clock_gettime(clockid_t, struct timespec *)
  __attribute__((weak, alias("__vdso_clock_gettime")));

int __vdso_getcpu() {
  return 0;
}

long getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache)
  __attribute__((weak, alias("__vdso_getcpu")));
