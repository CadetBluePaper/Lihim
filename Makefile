CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lgpgme

all: lihim lihim-host

vault.o: vault.c vault.h
	$(CC) $(CFLAGS) -c vault.c

lihim: main.c vault.o
	$(CC) $(CFLAGS) -o $@ main.c vault.o $(LDFLAGS)

lihim-host: native_host.c vault.o
	$(CC) $(CFLAGS) -o $@ native_host.c vault.o $(LDFLAGS)

clean:
	rm -f *.o lihim lihim-host

install: lihim lihim-host
	install -m 755 lihim /usr/local/bin/lihim
	install -m 755 lihim-host /usr/local/bin/lihim-host
