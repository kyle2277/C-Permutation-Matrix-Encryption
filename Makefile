# Makefile for FontBlanc_C
# Copyrite (c) Kyle Won, 2021

# Flags for FontBlanc_C source code 
CFLAGS = -Wall -Wextra -Werror -Wpedantic -std=c11
# Flags for CSparse dependencies
CFLAGS_DEP = -std=c11
CC = gcc
DEPENDENCIES = Dependencies/csparse.c Dependencies/csparse.h Dependencies/st_to_cc.c Dependencies/st_to_cc.h

all			:	fontblanc
fontblanc		:	fontblanc_main.o fontblanc.o util.o csparse.o st_to_cc.o
				$(CC) $(CFLAGS) -lm -o fontblanc fontblanc_main.c fontblanc.o util.o csparse.o st_to_cc.o
fontblanc_main.o	:	fontblanc_main.c
				$(CC) $(CFLAGS) -c fontblanc_main.c
fontblanc.o		:	fontblanc.c fontblanc.h
				$(CC) $(CFLAGS) -c fontblanc.c
util.o			:	util.c util.h
				$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=1 -c util.c
csparse.o		:	Dependencies/csparse.c Dependencies/csparse.h
				$(CC) $(CFLAGS_DEP) -c Dependencies/csparse.c
st_to_cc.o		:	Dependencies/st_to_cc.c Dependencies/st_to_cc.h
				$(CC) $(CFLAGS_DEP) -c Dependencies/st_to_cc.c
clean			:
				rm -f fontblanc *.o
infer			:
				make clean; infer capture -- make; infer analyze -- make
