# Makefile for DNS relay program
# Author: Hu Yongjian

CC:=gcc
all: dnsrelay clean
dnsrelay: main.o utils.o
	$(CC) -o dnsrelay main.o utils.o

main.o: dnsrelay.c dnsrelay.h dnsutils.h
	$(CC) -o main.o -c dnsrelay.c

utils.o: dnsutils.c dnsutils.h
	$(CC) -o utils.o -c dnsutils.c

.PHONY: clean
clean:
	rm -f *.o
