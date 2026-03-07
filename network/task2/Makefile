CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lnet

all: attacker

attacker: src/attacker.c
	$(CC) $(CFLAGS) -o attacker src/attacker.c $(LIBS)

clean:
	rm -f server client