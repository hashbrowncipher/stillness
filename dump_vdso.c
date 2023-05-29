#define SYS_write 0x01
#define SYS_pause 0x22
#define SYS_exit_group 0xe7

static inline long syscall(long nr, long rdi, long rsi, long rdx) {
  long ret;
  asm volatile
    ("syscall":"=a" (ret)
     //                 EDI      RSI       RDX
     :"a"(nr), "D"(rdi), "S"(rsi), "d"(rdx)
     :"rcx", "r11", "memory");
  return ret;
}

const char newline[] = { 0x10 };

void _start() {
  char *stack;
asm("mov %%rbp, %0":"=r"(stack));
  stack += 8;			// presumably a return value
  int zeroes;
  while(zeroes < 2) {
    stack += 8;
    long val = *(long *) stack;
    if(val == 0) {
      zeroes++;
    }
  }

  stack += 8;
  while(1) {
    long val = *(long *) stack;
    if(val == 0) {
      break;
    }

    if(val == 33) {
      stack += 8;
      break;
    }

    stack += 16;
  }

  char *vdso = *(long *) stack;
  syscall(SYS_write, 1, vdso, 8192);
  syscall(SYS_exit_group, 0, 0, 0);
}
