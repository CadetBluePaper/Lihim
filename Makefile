CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lgpme

VAULT_SRCS = vault.c

all: lihim lihim-host

lihim: main.c vault.o
 	$(CC) $(CFLAGS) -o $@ main.c vault.o $(LDFLAGS)

lihim-host: native_host.c vault.o
	$(CC) $(CFLAGS) -o $@ native_host.c vault.o $(LDFLAGS)

vault.o: vault.c vault.h
	$(CC) $(CFLAGS) -c vault.c

clean:
	rm -f *.o lihim lihim-host

install: lihim lihim-host
	install -m 755 lihim /usr/local/bin/lihim
	install -m 755 lihim-host /usr/local/lihim-host
