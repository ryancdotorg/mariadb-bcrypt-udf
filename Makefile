CC = gcc
CFLAGS = $(shell grep '^CFLAGS = ' crypt_blowfish/Makefile | cut -d= -f2-)
CFLAGS += -Wno-missing-prototypes -Wno-unused-parameter -Wno-undef -Wno-strict-prototypes
.PHONY: crypt_blowfish

all: bcrypt.so

bcrypt.o: bcrypt.c
	gcc -Wall -fPIC $(CFLAGS) -I/usr/include/mariadb -o $@ -c $<

bcrypt.so: bcrypt.o crypt_blowfish
	gcc -Wall -fPIC $(LDFLAGS) -shared bcrypt.o crypt_blowfish/*.o -o $@

crypt_blowfish:
	$(MAKE) -C crypt_blowfish

.PHONY: clean
clean:
	rm -f *.o bcrypt.so
	$(MAKE) -C crypt_blowfish clean
