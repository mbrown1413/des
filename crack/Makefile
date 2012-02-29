
all: check_keys

check_keys: check_keys.c input.h ../include/sbox.h
	$(CC) -std=c99 -Werror -pedantic -O3 -lm -Wno-missing-prototypes -I../include/ check_keys.c -o check_keys
