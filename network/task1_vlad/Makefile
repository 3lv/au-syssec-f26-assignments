CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lnet -lcrypto

all: server client

server: src/server.c src/crypto.c
	$(CC) $(CFLAGS) -o server src/server.c src/crypto.c $(LIBS)

client: src/client.c src/crypto.c
	$(CC) $(CFLAGS) -o client src/client.c src/crypto.c $(LIBS)

clean:
	rm -f server client