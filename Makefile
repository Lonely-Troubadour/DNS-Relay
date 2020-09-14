# Makefile for DNS relay program
# Author: Hu Yongjian

ifeq ($(OS), Windows_NT)
	detected_os = Windows
	LDFLAGS += -lwsock32
else
	detected_os = $(shell uname -s)
endif

CC:=gcc
all: dnsrelay clean

dnsrelay: main.o dnsutils.o dbutils.o utils.o
	$(CC) -o dnsrelay main.o dnsutils.o dbutils.o utils.o $(LDFLAGS)

main.o: dnsrelay.c dnsrelay.h dnsutils.h dbutils.h 
	$(CC) -o main.o -c dnsrelay.c $(LDFLAGS)

dnsutils.o: dnsutils.c dnsutils.h
	$(CC) -o dnsutils.o -c dnsutils.c $(LDFLAGS)

dbutils.o: dbutils.c dbutils.h
	$(CC) -o dbutils.o -c dbutils.c

utils.o: utils.c dnsrelay.h dnsutils.h
	$(CC) -o utils.o -c utils.c

.PHONY: clean
ifeq ($(detected_os), Windows)
clean:
	-@del *.o -rf
else
clean:
	-@rm -f *.o
endif
