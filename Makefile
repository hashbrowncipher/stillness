.PHONY: indent
CCFLAGS := -O2 -std=c11 -Wall -Wextra -Werror

all: stillness gettimeofday

vdso.so: vdso.so.dbg
	objcopy -S --remove-section __ex_table $< $@

vdso.so.dbg: vdso-layout.lds vclock_gettime.o
	ld -nostdlib -o $@ -shared --hash-style=both --build-id=sha1 --eh-frame-hdr -Bsymbolic -m elf_x86_64 --no-undefined -z max-page-size=4096 -T vdso-layout.lds vclock_gettime.o

vdso-data.s: vdso.so
	touch $@

vdso-layout.lds: vdso-layout.lds.S
	cc -E $< > $@

vclock_gettime.o: vclock_gettime.c

stillness: stillness.o vdso-data.o

gettimeofday: gettimeofday.c
	$(CC) $(CFLAGS) -o $@ $<

indent:
	indent -br -brs -brf -npsl -nsai -nsaf -nsaw -npcs *.c

dump_vdso: dump_vdso.c
	gcc -static -nostdlib -nostartfiles -o $@ $<

main: main.o
