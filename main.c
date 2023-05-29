#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/auxv.h>

int main() {
  void *vdso = getauxval(AT_SYSINFO_EHDR);
  int foo = 0;
  printf("%d\n", foo += 5);
  struct timespec ts;
  //clock_gettime(CLOCK_REALTIME, &ts);
  fprintf(stderr, "%ld.%09ld\n", ts.tv_sec, ts.tv_nsec);
}
