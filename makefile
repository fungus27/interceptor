CC := gcc
CFLAGS := -fsanitize=address -g
LDFLAGS := -fsanitize=address -g

main: main.o socks5.o

socks5.o: socks5.c socks5.h
