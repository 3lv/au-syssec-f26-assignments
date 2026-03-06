# Create a simple makefile to compile the server and client programs using the libpcap and libnet libs
CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lnet

all: server client

server: src/server.c
	$(CC) $(CFLAGS) -o server src/server.c $(LIBS)

client: src/client.c
	$(CC) $(CFLAGS) -o client src/client.c $(LIBS)

clean:
	rm -f server client