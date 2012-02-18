
all: check_keys

check_keys: check_keys.c
	$(CC) -std=c99 -Werror -pedantic -O3 -lm -Wno-missing-prototypes check_keys.c -o check_keys
