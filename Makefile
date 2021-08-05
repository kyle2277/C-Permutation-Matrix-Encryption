# Makefile for C Permutation Matrix Encryption (CPME)
# Copyrite (c) Kyle Won, 2021

# Flags for CPME source code
CFLAGS = -Wall -Wextra -Werror -Wpedantic -std=c11
# Flags for CSparse dependencies
CFLAGS_DEP = -std=c11
CC = gcc
DEPENDENCIES = Dependencies/csparse.c Dependencies/csparse.h Dependencies/st_to_cc.c Dependencies/st_to_cc.h

all			:	cpme
cpme		:	cpme_main.o cpme.o util.o csparse.o st_to_cc.o
				$(CC) $(CFLAGS) -lm -lpthread -o cpme cpme_main.c cpme.o util.o csparse.o st_to_cc.o
cpme_main.o	:	cpme_main.c
				$(CC) $(CFLAGS) -c cpme_main.c
cpme.o		:	cpme.c cpme.h
				$(CC) $(CFLAGS) -c cpme.c
util.o			:	util.c util.h
				$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=1 -c util.c
csparse.o		:	Dependencies/csparse.c Dependencies/csparse.h
				$(CC) $(CFLAGS_DEP) -c Dependencies/csparse.c
st_to_cc.o		:	Dependencies/st_to_cc.c Dependencies/st_to_cc.h
				$(CC) $(CFLAGS_DEP) -c Dependencies/st_to_cc.c
clean			:
				rm -f cpme *.o
infer			:
				make clean; infer capture -- make; infer analyze -- make
