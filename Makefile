# Makefile for DNS relay program
# Author: Hu Yongjian

CC:=gcc
all: dnsrelay clean
dnsrelay: main.o dnsutils.o dbutils.o
	$(CC) -o dnsrelay main.o dnsutils.o dbutils.o

main.o: dnsrelay.c dnsrelay.h dnsutils.h dbutils.h
	$(CC) -o main.o -c dnsrelay.c

dnsutils.o: dnsutils.c dnsutils.h
	$(CC) -o dnsutils.o -c dnsutils.c

dbutils.o: dbutils.c dbutils.h
	$(CC) -o dbutils.o -c dbutils.c

.PHONY: clean
clean:
	rm -f *.o
