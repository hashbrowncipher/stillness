#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

extern char vdso_start[];
extern char vdso_end[];

int main() {
	char * vdso = vdso_start;
	size_t len = vdso_end - vdso_start;
	fprintf(stderr, "%lx\n", &vdso_start);
	int fd = open("/proc/self/exe", O_RDONLY);
	char * buf = malloc(16384);
	size_t maps_len = read(fd, buf, 16384);
	write(STDOUT_FILENO, buf, maps_len);
}
