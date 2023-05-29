#include <time.h>

int __vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
        return 0;
}

int clock_gettime(clockid_t, struct timespec *)
        __attribute__((weak, alias("__vdso_clock_gettime")));
