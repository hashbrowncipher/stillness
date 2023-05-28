.PHONY: indent
CCFLAGS := -std=c11 -Wall -Wextra -Werror

all: stillness gettimeofday

stillness: stillness.c
	$(CC) $(CFLAGS) -o $@ $<

gettimeofday: gettimeofday.c
	$(CC) $(CFLAGS) -o $@ $<

indent:
	indent -br -brs -brf -npsl -nsai -nsaf -nsaw -npcs *.c

