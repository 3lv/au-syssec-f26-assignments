CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap -lnet
LIBS_MITM = -lnetfilter_queue

all: attacker attacker_mitm attacker_mitm_no_variable_length

attacker: src/attacker.c
	$(CC) $(CFLAGS) -o attacker src/attacker.c $(LIBS)

attacker_mitm: src/attacker_mitm.c
	$(CC) $(CFLAGS) -o attacker_mitm src/attacker_mitm.c $(LIBS_MITM)

attacker_mitm_no_variable_length: src/attacker_mitm_no_variable_length.c
	$(CC) $(CFLAGS) -o attacker_mitm_no_variable_length src/attacker_mitm_no_variable_length.c $(LIBS_MITM)

clean:
	rm -f attacker attacker_mitm attacker_mitm_no_variable_length