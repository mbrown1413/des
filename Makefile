
all: des des_64

des: des.c
	$(CC) -std=c99 -O3 -Werror -Wno-missing-prototypes des.c -o des

des_64: des_64.c include/
	$(CC) -std=c99 -O3 -Werror -Wno-missing-prototypes -Iinclude/ des_64.c -o des_64
