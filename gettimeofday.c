#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void run(bool print) {
  pid_t pid = getpid();
  struct timespec ts;
  assert(syscall(SYS_clock_gettime, CLOCK_REALTIME, &ts) == 0);
  if(print) {
    printf("[%d] clock_gettime(CLOCK_REALTIME): %lu.%09lu\n", pid, ts.tv_sec,
	   ts.tv_nsec);
  }

  assert(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) == 0);
  if(print) {
    printf("[%d] clock_gettime(CLOCK_MONOTONIC): %lu.%09lu\n", pid, ts.tv_sec,
	   ts.tv_nsec);
  }

  struct timeval tv;
  assert(syscall(SYS_gettimeofday, &tv, NULL) == 0);
  if(print) {
    printf("gettimeofday(): %lu.%06lu\n", tv.tv_sec, tv.tv_usec);
  }

  time_t time = syscall(SYS_time);
  if(print) {
    printf("time(): %lu\n", time);
  }


  syscall(SYS_time, &time);
  if(print) {
    printf("time(time_t): %lu\n", time);
  }
}

int main() {
  for(int i = 0; i < 100000; i++) {
    run(true);
  }
}
