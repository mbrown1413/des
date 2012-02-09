
/*
 * Ideas originally taken from this research paper by Eli Biham:
 *     "A Fast New DES Implementation in Software"
 * Specifically, Biham pointed out that 64 encryptions can be done in
 * parallel on 64 bit machines, and S-Boxes can be calculated with
 * simple gate logic.
 *
 * S-Box implementations with 55.4 gates average taken from:
 *     http://www.darkside.com.au/bitslice/
 *
 * John The Ripper has an implementation with less gates.  See:
 *     http://www.openwall.com/lists/john-users/2011/06/22/1
 *
 */

#define _BSD_SOURCE 1
#include <endian.h>  // Endian swapping routines

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Number of bits that will be searched.  The least significant NUM_CHUNK_BITS
// in the key space will be exhaustively searched.  Must be at least 6, since
// 64 decryptions are done simultaneously.
#define NUM_CHUNK_BITS 28

static const unsigned char left_block_order[32] = {
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
static const unsigned char right_block_order[32] = {
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
};
static const unsigned char encrypt_output_order[64] = {
    // Right block order
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,

    // Left block order
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const unsigned char feistel_input_orders[2][48] = {
    {
         6, 56, 48, 40, 32, 24,
        32, 24, 16,  8,  0, 58,
         0, 58, 50, 42, 34, 26,
        34, 26, 18, 10,  2, 60,
         2, 60, 52, 44, 36, 28,
        36, 28, 20, 12,  4, 62,
         4, 62, 54, 46, 38, 30,
        38, 30, 22, 14,  6, 56
    },
    {
         7, 57, 49, 41, 33, 25,
        33, 25, 17,  9,  1, 59,
         1, 59, 51, 43, 35, 27,
        35, 27, 19, 11,  3, 61,
         3, 61, 53, 45, 37, 29,
        37, 29, 21, 13,  5, 63,
         5, 63, 55, 47, 39, 31,
        39, 31, 23, 15,  7, 57
    },
};

static const unsigned char feistel_output_order[32] = {
     8, 16, 22, 30, 12, 27,  1, 17,
    23, 15, 29,  5, 25, 19,  9,  0,
     7, 13, 24,  2,  3, 28, 10, 18,
    31, 11, 21,  6,  4, 26, 14, 20
};

/*
 * Each of these 16 arrays represents which bits from the key make up the ith
 * subkey.  These indexes are based on a 56 bit key (with the parity bits taken
 * out).  The subkey order is reversed for decryption.
 */
static const unsigned char key_bit_orders[16][48] = {
    {  // Subkey 15
         15, 51, 36,  2, 49, 21,
         35, 31,  8, 14, 23, 43,
          9, 37, 29, 28, 45,  0,
          1,  7, 38, 30, 22, 42,
         26,  4, 41, 54, 39, 10,
         48, 33, 11, 53, 27, 32,
          5, 25, 40,  3, 20, 24,
         46, 19, 18,  6, 55, 34,
    },
    {  // Subkey 14
         22,  1, 43,  9, 31, 28,
         42, 38, 15, 21, 30, 50,
         16, 44, 36, 35, 52,  7,
          8, 14, 45, 37, 29, 49,
         33, 11, 48,  6, 46, 17,
         55, 40, 18,  5, 34, 39,
         12, 32, 47, 10, 27,  4,
         53, 26, 25, 13,  3, 41,
    },
    {  // Subkey 13
         36, 15,  0, 23, 45, 42,
         31, 52, 29, 35, 44,  7,
         30,  1, 50, 49,  9, 21,
         22, 28,  2, 51, 43, 38,
         47, 25,  3, 20,  5,  4,
         10, 54, 32, 19, 48, 53,
         26, 46,  6, 24, 41, 18,
         12, 40, 39, 27, 17, 55,
    },
    {  // Subkey 12
         50, 29, 14, 37,  2, 31,
         45,  9, 43, 49,  1, 21,
         44, 15,  7, 38, 23, 35,
         36, 42, 16,  8,  0, 52,
          6, 39, 17, 34, 19, 18,
         24, 13, 46, 33,  3, 12,
         40,  5, 20, 11, 55, 32,
         26, 54, 53, 41,  4, 10,
    },
    {  // Subkey 11
          7, 43, 28, 51, 16, 45,
          2, 23,  0, 38, 15, 35,
          1, 29, 21, 52, 37, 49,
         50, 31, 30, 22, 14,  9,
         20, 53,  4, 48, 33, 32,
         11, 27,  5, 47, 17, 26,
         54, 19, 34, 25, 10, 46,
         40, 13, 12, 55, 18, 24,
    },
    {  // Subkey 10
         21,  0, 42,  8, 30,  2,
         16, 37, 14, 52, 29, 49,
         15, 43, 35,  9, 51, 38,
          7, 45, 44, 36, 28, 23,
         34, 12, 18,  3, 47, 46,
         25, 41, 19,  6,  4, 40,
         13, 33, 48, 39, 24,  5,
         54, 27, 26, 10, 32, 11,
    },
    {  // Subkey 9
         35, 14, 31, 22, 44, 16,
         30, 51, 28,  9, 43, 38,
         29,  0, 49, 23,  8, 52,
         21,  2,  1, 50, 42, 37,
         48, 26, 32, 17,  6,  5,
         39, 55, 33, 20, 18, 54,
         27, 47,  3, 53, 11, 19,
         13, 41, 40, 24, 46, 25,
    },
    {  // Subkey 8
         49, 28, 45, 36,  1, 30,
         44,  8, 42, 23,  0, 52,
         43, 14, 38, 37, 22,  9,
         35, 16, 15,  7, 31, 51,
          3, 40, 46,  4, 20, 19,
         53, 10, 47, 34, 32, 13,
         41,  6, 17, 12, 25, 33,
         27, 55, 54, 11,  5, 39,
    },
    {  // Subkey 7
         31, 35, 52, 43,  8, 37,
         51, 15, 49, 30,  7,  2,
         50, 21, 45, 44, 29, 16,
         42, 23, 22, 14, 38,  1,
         10, 47, 53, 11, 27, 26,
          5, 17, 54, 41, 39, 20,
         48, 13, 24, 19, 32, 40,
         34,  3,  6, 18, 12, 46,
    },
    {  // Subkey 6
         45, 49,  9,  0, 22, 51,
          8, 29, 38, 44, 21, 16,
          7, 35,  2,  1, 43, 30,
         31, 37, 36, 28, 52, 15,
         24,  6, 12, 25, 41, 40,
         19,  4, 13, 55, 53, 34,
          3, 27, 11, 33, 46, 54,
         48, 17, 20, 32, 26,  5,
    },
    {  // Subkey 5
          2, 38, 23, 14, 36,  8,
         22, 43, 52,  1, 35, 30,
         21, 49, 16, 15,  0, 44,
         45, 51, 50, 42,  9, 29,
         11, 20, 26, 39, 55, 54,
         33, 18, 27, 10, 12, 48,
         17, 41, 25, 47,  5, 13,
          3,  4, 34, 46, 40, 19,
    },
    {  // Subkey 4
         16, 52, 37, 28, 50, 22,
         36,  0,  9, 15, 49, 44,
         35, 38, 30, 29, 14,  1,
          2,  8,  7, 31, 23, 43,
         25, 34, 40, 53, 10, 13,
         47, 32, 41, 24, 26,  3,
          4, 55, 39,  6, 19, 27,
         17, 18, 48,  5, 54, 33,
    },
    {  // Subkey 3
         30,  9, 51, 42,  7, 36,
         50, 14, 23, 29, 38,  1,
         49, 52, 44, 43, 28, 15,
         16, 22, 21, 45, 37,  0,
         39, 48, 54, 12, 24, 27,
          6, 46, 55, 11, 40, 17,
         18, 10, 53, 20, 33, 41,
          4, 32,  3, 19, 13, 47,
    },
    {  // Subkey 2
         44, 23,  8, 31, 21, 50,
          7, 28, 37, 43, 52, 15,
         38,  9,  1,  0, 42, 29,
         30, 36, 35,  2, 51, 14,
         53,  3, 13, 26, 11, 41,
         20,  5, 10, 25, 54,  4,
         32, 24, 12, 34, 47, 55,
         18, 46, 17, 33, 27,  6,
    },
    {  // Subkey 1
          1, 37, 22, 45, 35,  7,
         21, 42, 51,  0,  9, 29,
         52, 23, 15, 14, 31, 43,
         44, 50, 49, 16,  8, 28,
         12, 17, 27, 40, 25, 55,
         34, 19, 24, 39, 13, 18,
         46, 11, 26, 48,  6, 10,
         32,  5,  4, 47, 41, 20,
    },
    {  // Subkey 0
          8, 44, 29, 52, 42, 14,
         28, 49,  1,  7, 16, 36,
          2, 30, 22, 21, 38, 50,
         51,  0, 31, 23, 15, 35,
         19, 24, 34, 47, 32,  3,
         41, 26,  4, 46, 20, 25,
         53, 18, 33, 55, 13, 17,
         39, 12, 11, 54, 48, 27,
    }
};

static const unsigned char final_permutation[64] = {
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
    32, 0, 40,  8, 48, 16, 56, 24
};

void print_uint64(uint64_t input) {
    input = htobe64(input);
    unsigned char* ptr = (unsigned char*) &input;
    printf("0x");
    for (int i=0; i<8; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
}

void print_uint64_block(const uint64_t inputs[64]) {
    for (int inputnum=0; inputnum<64; inputnum++) {
        uint64_t input = htobe64(inputs[inputnum]);
        unsigned char* ptr = (unsigned char*) &input;
        printf("0x");
        for (int i=0; i<8; i++) {
            printf("%02x", ptr[i]);
        }
        if (inputnum == 63) {
            printf("\n");
        } else if (inputnum%8 == 7 && inputnum != 0) {
            printf(",\n");
        } else {
            printf(", ");
        }
    }
}

static void s0(
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50, x51, x52, x53, x54, x55, x56;

    x1 = a3 & ~a5;
    x2 = x1 ^ a4;
    x3 = a3 & ~a4;
    x4 = x3 | a5;
    x5 = a6 & x4;
    x6 = x2 ^ x5;
    x7 = a4 & ~a5;
    x8 = a3 ^ a4;
    x9 = a6 & ~x8;
    x10 = x7 ^ x9;
    x11 = a2 | x10;
    x12 = x6 ^ x11;
    x13 = a5 ^ x5;
    x14 = x13 & x8;
    x15 = a5 & ~a4;
    x16 = x3 ^ x14;
    x17 = a6 | x16;
    x18 = x15 ^ x17;
    x19 = a2 | x18;
    x20 = x14 ^ x19;
    x21 = a1 & x20;
    x22 = x12 ^ ~x21;
    *out2 = x22;
    x23 = x1 | x5;
    x24 = x23 ^ x8;
    x25 = x18 & ~x2;
    x26 = a2 & ~x25;
    x27 = x24 ^ x26;
    x28 = x6 | x7;
    x29 = x28 ^ x25;
    x30 = x9 ^ x24;
    x31 = x18 & ~x30;
    x32 = a2 & x31;
    x33 = x29 ^ x32;
    x34 = a1 & x33;
    x35 = x27 ^ x34;
    *out4 = x35;
    x36 = a3 & x28;
    x37 = x18 & ~x36;
    x38 = a2 | x3;
    x39 = x37 ^ x38;
    x40 = a3 | x31;
    x41 = x24 & ~x37;
    x42 = x41 | x3;
    x43 = x42 & ~a2;
    x44 = x40 ^ x43;
    x45 = a1 & ~x44;
    x46 = x39 ^ ~x45;
    *out1 = x46;
    x47 = x33 & ~x9;
    x48 = x47 ^ x39;
    x49 = x4 ^ x36;
    x50 = x49 & ~x5;
    x51 = x42 | x18;
    x52 = x51 ^ a5;
    x53 = a2 & ~x52;
    x54 = x50 ^ x53;
    x55 = a1 | x54;
    x56 = x48 ^ ~x55;
    *out3 = x56;
}

static void s1(
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50;

    x1 = a1 ^ a6;
    x2 = x1 ^ a5;
    x3 = a6 & a5;
    x4 = a1 & ~x3;
    x5 = a2 & ~x4;
    x6 = x2 ^ x5;
    x7 = x3 | x5;
    x8 = x7 & ~x1;
    x9 = a3 | x8;
    x10 = x6 ^ x9;
    x11 = a5 & ~x4;
    x12 = x11 | a2;
    x13 = a4 & x12;
    x14 = x10 ^ ~x13;
    *out1 = x14;
    x15 = x4 ^ x14;
    x16 = x15 & ~a2;
    x17 = x2 ^ x16;
    x18 = a6 & ~x4;
    x19 = x6 ^ x11;
    x20 = a2 & x19;
    x21 = x18 ^ x20;
    x22 = a3 & x21;
    x23 = x17 ^ x22;
    x24 = a5 ^ a2;
    x25 = x24 & ~x8;
    x26 = x6 | a1;
    x27 = x26 ^ a2;
    x28 = a3 & ~x27;
    x29 = x25 ^ x28;
    x30 = a4 | x29;
    x31 = x23 ^ x30;
    *out3 = x31;
    x32 = x18 | x25;
    x33 = x32 ^ x10;
    x34 = x27 | x20;
    x35 = a3 & x34;
    x36 = x33 ^ x35;
    x37 = x24 & x34;
    x38 = x12 & ~x37;
    x39 = a4 | x38;
    x40 = x36 ^ ~x39;
    *out4 = x40;
    x41 = a2 ^ x2;
    x42 = x41 & ~x33;
    x43 = x42 ^ x29;
    x44 = a3 & ~x43;
    x45 = x41 ^ x44;
    x46 = x3 | x20;
    x47 = a3 & x3;
    x48 = x46 ^ x47;
    x49 = a4 & ~x48;
    x50 = x45 ^ ~x49;
    *out2 = x50;
}


static void
s2 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50, x51, x52, x53;

    x1 = a2 ^ a3;
    x2 = x1 ^ a6;
    x3 = a2 & x2;
    x4 = a5 | x3;
    x5 = x2 ^ x4;
    x6 = a3 ^ x3;
    x7 = x6 & ~a5;
    x8 = a1 | x7;
    x9 = x5 ^ x8;
    x10 = a6 & ~x3;
    x11 = x10 ^ a5;
    x12 = a1 & x11;
    x13 = a5 ^ x12;
    x14 = a4 | x13;
    x15 = x9 ^ x14;
    *out4 = x15;
    x16 = a3 & a6;
    x17 = x16 | x3;
    x18 = x17 ^ a5;
    x19 = x2 & ~x7;
    x20 = x19 ^ x16;
    x21 = a1 | x20;
    x22 = x18 ^ x21;
    x23 = a2 | x7;
    x24 = x23 ^ x4;
    x25 = x11 | x19;
    x26 = x25 ^ x17;
    x27 = a1 | x26;
    x28 = x24 ^ x27;
    x29 = a4 & ~x28;
    x30 = x22 ^ ~x29;
    *out3 = x30;
    x31 = a3 & a5;
    x32 = x31 ^ x2;
    x33 = x7 & ~a3;
    x34 = a1 | x33;
    x35 = x32 ^ x34;
    x36 = x10 | x26;
    x37 = a6 ^ x17;
    x38 = x37 & ~x5;
    x39 = a1 & x38;
    x40 = x36 ^ x39;
    x41 = a4 & x40;
    x42 = x35 ^ x41;
    *out2 = x42;
    x43 = a2 | x19;
    x44 = x43 ^ x18;
    x45 = a6 & x15;
    x46 = x45 ^ x6;
    x47 = x46 & ~a1;
    x48 = x44 ^ x47;
    x49 = x42 & ~x23;
    x50 = a1 | x49;
    x51 = x47 ^ x50;
    x52 = a4 & x51;
    x53 = x48 ^ ~x52;
    *out1 = x53;
}


static void
s3 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39;

    x1 = a1 | a3;
    x2 = a5 & x1;
    x3 = a1 ^ x2;
    x4 = a2 | a3;
    x5 = x3 ^ x4;
    x6 = a3 & ~a1;
    x7 = x6 | x3;
    x8 = a2 & x7;
    x9 = a5 ^ x8;
    x10 = a4 & x9;
    x11 = x5 ^ x10;
    x12 = a3 ^ x2;
    x13 = a2 & ~x12;
    x14 = x7 ^ x13;
    x15 = x12 | x3;
    x16 = a3 ^ a5;
    x17 = x16 & ~a2;
    x18 = x15 ^ x17;
    x19 = a4 | x18;
    x20 = x14 ^ x19;
    x21 = a6 | x20;
    x22 = x11 ^ x21;
    *out1 = x22;
    x23 = a6 & x20;
    x24 = x23 ^ ~x11;
    *out2 = x24;
    x25 = a2 & x9;
    x26 = x25 ^ x15;
    x27 = a3 ^ x8;
    x28 = x27 ^ x17;
    x29 = a4 & ~x28;
    x30 = x26 ^ x29;
    x31 = x11 ^ x30;
    x32 = a2 & ~x31;
    x33 = x22 ^ x32;
    x34 = x31 & ~a4;
    x35 = x33 ^ x34;
    x36 = a6 | x35;
    x37 = x30 ^ ~x36;
    *out3 = x37;
    x38 = x23 ^ x35;
    x39 = x38 ^ x37;
    *out4 = x39;
}


static void
s4 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50, x51, x52, x53, x54, x55, x56;

    x1 = a3 & ~a4;
    x2 = x1 ^ a1;
    x3 = a1 & ~a3;
    x4 = a6 | x3;
    x5 = x2 ^ x4;
    x6 = a4 ^ a1;
    x7 = x6 | x1;
    x8 = x7 & ~a6;
    x9 = a3 ^ x8;
    x10 = a5 | x9;
    x11 = x5 ^ x10;
    x12 = a3 & x7;
    x13 = x12 ^ a4;
    x14 = x13 & ~x3;
    x15 = a4 ^ x3;
    x16 = a6 | x15;
    x17 = x14 ^ x16;
    x18 = a5 | x17;
    x19 = x13 ^ x18;
    x20 = x19 & ~a2;
    x21 = x11 ^ x20;
    *out4 = x21;
    x22 = a4 & x4;
    x23 = x22 ^ x17;
    x24 = a1 ^ x9;
    x25 = x2 & x24;
    x26 = a5 & ~x25;
    x27 = x23 ^ x26;
    x28 = a4 | x24;
    x29 = x28 & ~a2;
    x30 = x27 ^ x29;
    *out2 = x30;
    x31 = x17 & x5;
    x32 = x7 & ~x31;
    x33 = x8 & ~a4;
    x34 = x33 ^ a3;
    x35 = a5 & x34;
    x36 = x32 ^ x35;
    x37 = x13 | x16;
    x38 = x9 ^ x31;
    x39 = a5 | x38;
    x40 = x37 ^ x39;
    x41 = a2 | x40;
    x42 = x36 ^ ~x41;
    *out3 = x42;
    x43 = x19 & ~x32;
    x44 = x43 ^ x24;
    x45 = x27 | x43;
    x46 = x45 ^ x6;
    x47 = a5 & ~x46;
    x48 = x44 ^ x47;
    x49 = x6 & x38;
    x50 = x49 ^ x34;
    x51 = x21 ^ x38;
    x52 = x28 & ~x51;
    x53 = a5 & x52;
    x54 = x50 ^ x53;
    x55 = a2 | x54;
    x56 = x48 ^ x55;
    *out1 = x56;
}


static void
s5 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50, x51, x52, x53;

    x1 = a5 ^ a1;
    x2 = x1 ^ a6;
    x3 = a1 & a6;
    x4 = x3 & ~a5;
    x5 = a4 & ~x4;
    x6 = x2 ^ x5;
    x7 = a6 ^ x3;
    x8 = x4 | x7;
    x9 = x8 & ~a4;
    x10 = x7 ^ x9;
    x11 = a2 & x10;
    x12 = x6 ^ x11;
    x13 = a6 | x6;
    x14 = x13 & ~a5;
    x15 = x4 | x10;
    x16 = a2 & ~x15;
    x17 = x14 ^ x16;
    x18 = x17 & ~a3;
    x19 = x12 ^ ~x18;
    *out1 = x19;
    x20 = x19 & ~x1;
    x21 = x20 ^ x15;
    x22 = a6 & ~x21;
    x23 = x22 ^ x6;
    x24 = a2 & ~x23;
    x25 = x21 ^ x24;
    x26 = a5 | a6;
    x27 = x26 & ~x1;
    x28 = a2 & ~x24;
    x29 = x27 ^ x28;
    x30 = a3 & ~x29;
    x31 = x25 ^ ~x30;
    *out4 = x31;
    x32 = x3 ^ x6;
    x33 = x32 & ~x10;
    x34 = a6 ^ x25;
    x35 = a5 & ~x34;
    x36 = a2 & ~x35;
    x37 = x33 ^ x36;
    x38 = x21 & ~a5;
    x39 = a3 | x38;
    x40 = x37 ^ ~x39;
    *out3 = x40;
    x41 = x35 | x2;
    x42 = a5 & x7;
    x43 = a4 & ~x42;
    x44 = a2 | x43;
    x45 = x41 ^ x44;
    x46 = x23 | x35;
    x47 = x46 ^ x5;
    x48 = x26 & x33;
    x49 = x48 ^ x2;
    x50 = a2 & x49;
    x51 = x47 ^ x50;
    x52 = a3 & ~x51;
    x53 = x45 ^ ~x52;
    *out2 = x53;
}


static void
s6 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50, x51;

    x1 = a2 & a4;
    x2 = x1 ^ a5;
    x3 = a4 & x2;
    x4 = x3 ^ a2;
    x5 = a3 & ~x4;
    x6 = x2 ^ x5;
    x7 = a3 ^ x5;
    x8 = a6 & ~x7;
    x9 = x6 ^ x8;
    x10 = a2 | a4;
    x11 = x10 | a5;
    x12 = a5 & ~a2;
    x13 = a3 | x12;
    x14 = x11 ^ x13;
    x15 = x3 ^ x6;
    x16 = a6 | x15;
    x17 = x14 ^ x16;
    x18 = a1 & x17;
    x19 = x9 ^ x18;
    *out1 = x19;
    x20 = a4 & ~a3;
    x21 = a2 & ~x20;
    x22 = a6 & x21;
    x23 = x9 ^ x22;
    x24 = a4 ^ x4;
    x25 = a3 | x3;
    x26 = x24 ^ x25;
    x27 = a3 ^ x3;
    x28 = x27 & a2;
    x29 = a6 & ~x28;
    x30 = x26 ^ x29;
    x31 = a1 | x30;
    x32 = x23 ^ ~x31;
    *out2 = x32;
    x33 = x7 ^ x30;
    x34 = a2 | x24;
    x35 = x34 ^ x19;
    x36 = x35 & ~a6;
    x37 = x33 ^ x36;
    x38 = x26 & ~a3;
    x39 = x38 | x30;
    x40 = x39 & ~a1;
    x41 = x37 ^ x40;
    *out3 = x41;
    x42 = a5 | x20;
    x43 = x42 ^ x33;
    x44 = a2 ^ x15;
    x45 = x24 & ~x44;
    x46 = a6 & x45;
    x47 = x43 ^ x46;
    x48 = a3 & x22;
    x49 = x48 ^ x46;
    x50 = a1 | x49;
    x51 = x47 ^ x50;
    *out4 = x51;
}


static void
s7 (
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5,
    uint64_t a6,
    uint64_t *out1,
    uint64_t *out2,
    uint64_t *out3,
    uint64_t *out4
) {
    uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, x29, x30, x31, x32;
    uint64_t x33, x34, x35, x36, x37, x38, x39, x40;
    uint64_t x41, x42, x43, x44, x45, x46, x47, x48;
    uint64_t x49, x50;

    x1 = a3 ^ a1;
    x2 = a1 & ~a3;
    x3 = x2 ^ a4;
    x4 = a5 | x3;
    x5 = x1 ^ x4;
    x6 = x5 & ~a1;
    x7 = x6 ^ a3;
    x8 = x7 & ~a5;
    x9 = a4 ^ x8;
    x10 = a2 & ~x9;
    x11 = x5 ^ x10;
    x12 = x6 | a4;
    x13 = x12 ^ x1;
    x14 = x13 ^ a5;
    x15 = x3 & ~x14;
    x16 = x15 ^ x7;
    x17 = a2 & ~x16;
    x18 = x14 ^ x17;
    x19 = a6 | x18;
    x20 = x11 ^ ~x19;
    *out1 = x20;
    x21 = x5 | a5;
    x22 = x21 ^ x3;
    x23 = x11 & ~a4;
    x24 = a2 & ~x23;
    x25 = x22 ^ x24;
    x26 = a1 & x21;
    x27 = a5 & x2;
    x28 = x27 ^ x23;
    x29 = a2 & x28;
    x30 = x26 ^ x29;
    x31 = x30 & ~a6;
    x32 = x25 ^ x31;
    *out3 = x32;
    x33 = a3 & ~x16;
    x34 = x9 | x33;
    x35 = a2 | x6;
    x36 = x34 ^ x35;
    x37 = x2 & ~x14;
    x38 = x22 | x32;
    x39 = a2 & ~x38;
    x40 = x37 ^ x39;
    x41 = a6 | x40;
    x42 = x36 ^ ~x41;
    *out2 = x42;
    x43 = x1 & ~a5;
    x44 = x43 | a4;
    x45 = a3 ^ a5;
    x46 = x45 ^ x37;
    x47 = x46 & ~a2;
    x48 = x44 ^ x47;
    x49 = a6 & x48;
    x50 = x11 ^ ~x49;
    *out4 = x50;
}

/*
 * Take 64 integers of length 64 and put the ith bit of input[j] into
 * the jth bit of output[i].  Think of this as writing every single bit
 * into a 64x64 matrix, then transposing that matrix.  Consequently,
 * function is its own inverse.
 */
void zip_64_bit(const uint64_t input[64], uint64_t output[64]) {
    memset(output, 0, 64*8);
    for (int bitnum=0; bitnum<64; bitnum++) {
        for (int blocknum=0; blocknum<64; blocknum++) {
            output[bitnum] |= ((input[blocknum] << bitnum) & 0x8000000000000000LL) >> blocknum;
        }
    }
}

/*
 * Like zip_64_bit, except it treats each input as only containing 56 bits (the
 * most significant 8 bits are ignored).  Consequently, the output is only 56
 * long.  Unlike zip_64_bit, this function is not its own inverse.
 */
void zip_56_bit(const uint64_t input[64], uint64_t output[56]) {
    memset(output, 0, 56*8);
    for (int bitnum=8; bitnum<64; bitnum++) {
        for (int blocknum=0; blocknum<64; blocknum++) {
            output[bitnum-8] |= ((input[blocknum] << bitnum) & 0x8000000000000000LL) >> blocknum;
        }
    }
}

void des_sboxes(const uint64_t block_bits[64], uint64_t output_bits[32]) {
    #define S(i) \
        s ## i ( \
            block_bits[i*6 + 0], \
            block_bits[i*6 + 1], \
            block_bits[i*6 + 2], \
            block_bits[i*6 + 3], \
            block_bits[i*6 + 4], \
            block_bits[i*6 + 5], \
            &output_bits[feistel_output_order[i*4 + 0]], \
            &output_bits[feistel_output_order[i*4 + 1]], \
            &output_bits[feistel_output_order[i*4 + 2]], \
            &output_bits[feistel_output_order[i*4 + 3]] \
        );

    //memset(output_bits, 0, 32*8);
    S(0);
    S(1);
    S(2);
    S(3);
    S(4);
    S(5);
    S(6);
    S(7);

    #undef S
}

void des_feistel(const uint64_t block_bits[64], const uint64_t key_bits[56], uint64_t output[32], int roundnum) {

    const unsigned char* key_bit_order = key_bit_orders[roundnum];
    const unsigned char* input_order = feistel_input_orders[roundnum%2];

    uint64_t temp[64];

    // Feistel Expansion (no op)
    // Already been accounted for in input_order.

    // Feistel Input XOR Subkey
    // The input bits are picked from block_bits in the order defined by
    // input_order.  The output is stored linearly.
    //const unsigned char* key_bit_order = key_bit_orders[roundnum];
    for (int i=0; i<48; i++) {
        temp[i] = block_bits[input_order[i]] ^ key_bits[key_bit_order[i]];
    }

    // S-Boxes
    des_sboxes(temp, output);

    // Feistel End Permutation (no op)

}

void des_decrypt(uint64_t block_bits[64], const uint64_t key_bits[56]) {

    uint64_t feistel_output[32];
    const unsigned char* real_left_block_order;

    // Initial Permutation (no op)

    for (int roundnum=0; roundnum<16; roundnum++) {

        // Account for blocks switching each round
        if (roundnum % 2 == 0) {
            real_left_block_order = left_block_order;
        } else {
            real_left_block_order = right_block_order;
        }

        // Feistel Function
        des_feistel(block_bits, key_bits, feistel_output, roundnum);

        // XOR Left Block and Feistel output
        for (int i=0; i<32; i++) {
            block_bits[real_left_block_order[i]] ^= feistel_output[i];
        }

        // Switch block halves (no op)

    }

    // Unswitch block halves (no op)
    // Reverse of this is performed on the plaintext before entry

    // Permute results into output_bits (no op)
    // Reverse of this is performed on the plaintext before entry

}

/*
 * Compares two zipped inputs.  Return a uint64_t in which each 0 represents a
 * match for that position.
 */
uint64_t compare(const uint64_t a[64], const uint64_t b[64]) {
    uint64_t result = 0LL;
    for (int i=0; i<64; i++) {
        result |= a[i] ^ b[i];
        if (result == 0xffffffffffffffff) {
            return result;
        }

    }
    return result;
}

void check_key_64(const uint64_t plaintext_zipped[64], const uint64_t ciphertext_zipped[64], const uint64_t keys_zipped[56]) {
    uint64_t temp[64];

    /*
    zip_56_bit(keys_zipped, temp);
    if (temp[0]&0x00FFFFFFFFFFFFFFLL == 0x000007FD6BCEC0LL) {
        printf("Yes\n");
    }
    */
    /*
    printf("\n");
    print_uint64_block(keys_zipped);
    */

    //TODO: Try rearranging things so this memcpy isn't needed.
    memcpy(temp, ciphertext_zipped, 64*8);

    des_decrypt(temp, keys_zipped);
    // temp is now plaintext zipped

    uint64_t comparison = compare(temp, plaintext_zipped);
    if (comparison != 0xffffffffffffffffLL) {
        //TODO: Print something more easily interpreted
        zip_64_bit(keys_zipped, temp);
        print_uint64_block(temp);
        printf("\n");
        printf("(comparison=0x%016qx)", ~comparison);
    }
}

void check_key_chunk(const uint64_t plaintext_zipped[64], const uint64_t ciphertext_zipped[64], uint64_t keys_zipped[56]) {
    for (int i=0; i<pow(2, (NUM_CHUNK_BITS-6)); i++) {

        check_key_64(plaintext_zipped, ciphertext_zipped, keys_zipped);

        // Increment keys_zipped
        for (int j=56-NUM_CHUNK_BITS; j<50; j++) {
            keys_zipped[j] ^= 0xffffffffffffffffLL;
            if (keys_zipped[j]) {
                break;
            }
        }

    }
}

int main(int argc, char** argv) {

    uint64_t plaintext_zipped[64] = {
        // Zipped 0x018945cddc549810 64 times
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL
    };
    //uint64_t plaintext[64];
    //zip_64_bit(plaintext, plaintext_zipped);

    uint64_t ciphertext_zipped[64] = {
        // Zipped 0x627870815363e4ff 64 times
        0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0xffffffffffffffffLL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0x0000000000000000LL,
        0x0000000000000000LL, 0xffffffffffffffffLL, 0x0000000000000000LL, 0x0000000000000000LL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL,
        0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL, 0xffffffffffffffffLL
    };
    //uint64_t ciphertext[64];
    //zip_64_bit(ciphertext, ciphertext_zipped);

    // These keys exclude the 8 unused key bits.  They start out at 0 to 63
    // (zipped), then the search starting point is added based on argv[1].
    uint64_t keys_zipped[56] = {
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x0000000000000000LL, 0x00000000ffffffffLL, 0x0000ffff0000ffffLL,
        0x00ff00ff00ff00ffLL, 0x0f0f0f0f0f0f0f0fLL, 0x3333333333333333LL, 0x5555555555555555LL
    };
    // Set the most significant (56-NUM_CHUNK_BITS) based on argv[1].  Each
    // char in argv[1] is '0' or '1' specifying what that bit for every key
    // will be set to.
    if (argv[1][56-NUM_CHUNK_BITS] != '\0') {
        printf("Incorrect Argument Size!\n");
        exit(-1);
    }
    for (int i=0; i<56-NUM_CHUNK_BITS; i++) {
        keys_zipped[i] = (argv[1][i]-48) * 0xffffffffffffffffLL;
    }

    /*
    uint64_t keys[64] = {
        // Count from 0 to 63
        0x00LL, 0x01LL, 0x02LL, 0x03LL,
        0x04LL, 0x05LL, 0x06LL, 0x07LL,
        0x08LL, 0x09LL, 0x0aLL, 0x0bLL,
        0x0cLL, 0x0dLL, 0x0eLL, 0x0fLL,
        0x10LL, 0x11LL, 0x12LL, 0x13LL,
        0x14LL, 0x15LL, 0x16LL, 0x17LL,
        0x18LL, 0x19LL, 0x1aLL, 0x1bLL,
        0x1cLL, 0x1dLL, 0x1eLL, 0x1fLL,
        0x20LL, 0x21LL, 0x22LL, 0x23LL,
        0x24LL, 0x25LL, 0x26LL, 0x27LL,
        0x28LL, 0x29LL, 0x2aLL, 0x2bLL,
        0x2cLL, 0x2dLL, 0x2eLL, 0x2fLL,
        0x30LL, 0x31LL, 0x32LL, 0x33LL,
        0x34LL, 0x35LL, 0x36LL, 0x37LL,
        0x38LL, 0x39LL, 0x3aLL, 0x3bLL,
        0x3cLL, 0x3dLL, 0x3eLL, 0x3fLL
    };
    //uint64_t starting_point = (uint64_t) atoll(argv[1]);
    for (int i=0; i<64; i++) {
        //keys[i] += 0x000007FD6BCEC9LL;
        keys[i] += 0x000007FD6BCEC0LL;
        // 0x0e29c6447b3a2cLL = 3986581203139116
    }
    zip_56_bit(keys, keys_zipped);
    /**/

    /*
    printf("\nKey Start (Zipped):\n");
    print_uint64_block(keys_zipped);
    printf("\n");
    */

    check_key_chunk(plaintext_zipped, ciphertext_zipped, keys_zipped);

}
