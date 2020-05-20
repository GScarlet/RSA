CC = gcc

INCLUDE = -I/usr/local/include -I/usr/include
LIB = -L/usr/local/lib -L/usr/lib -lgmp -g -std=c99 -Wall -lcrypto

all: rsa rsaOAEP

rsa: rsa.c
	$(CC) -o rsa $(INCLUDE) rsa.c $(LIB)

rsaOAEP: rsa_OAEP.c
	$(CC) -o rsaOAEP $(INCLUDE) rsa_OAEP.c $(LIB)

clean:
	-rm *.o 
	-rm rsa
	-rm rsaOAEP
