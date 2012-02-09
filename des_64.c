
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
 * subkey.
 */
static const unsigned char key_bit_orders[16][48] = {
    { // Subkey 0
         9, 50, 33, 59, 48, 16,
        32, 56,  1,  8, 18, 41,
         2, 34, 25, 24, 43, 57,
        58,  0, 35, 26, 17, 40,
        21, 27, 38, 53, 36,  3,
        46, 29,  4, 52, 22, 28,
        60, 20, 37, 62, 14, 19,
        44, 13, 12, 61, 54, 30
    },
    { // Subkey 1
         1, 42, 25, 51, 40,  8,
        24, 48, 58,  0, 10, 33,
        59, 26, 17, 16, 35, 49,
        50, 57, 56, 18,  9, 32,
        13, 19, 30, 45, 28, 62,
        38, 21, 27, 44, 14, 20,
        52, 12, 29, 54,  6, 11,
        36,  5,  4, 53, 46, 22
    },
    { // Subkey 2
        50, 26,  9, 35, 24, 57,
         8, 32, 42, 49, 59, 17,
        43, 10,  1,  0, 48, 33,
        34, 41, 40,  2, 58, 16,
        60,  3, 14, 29, 12, 46,
        22,  5, 11, 28, 61,  4,
        36, 27, 13, 38, 53, 62,
        20, 52, 19, 37, 30, 6
    },
    { // Subkey 3
        34, 10, 58, 48,  8, 41,
        57, 16, 26, 33, 43,  1,
        56, 59, 50, 49, 32, 17,
        18, 25, 24, 51, 42,  0,
        44, 54, 61, 13, 27, 30,
         6, 52, 62, 12, 45, 19,
        20, 11, 60, 22, 37, 46,
         4, 36,  3, 21, 14, 53
    },
    { // Subkey 4
        18, 59, 42, 32, 57, 25,
        41,  0, 10, 17, 56, 50,
        40, 43, 34, 33, 16,  1,
         2,  9,  8, 35, 26, 49,
        28, 38, 45, 60, 11, 14,
        53, 36, 46, 27, 29,  3,
         4, 62, 44,  6, 21, 30,
        19, 20, 54,  5, 61, 37
    },
    { // Subkey 5
         2, 43, 26, 16, 41,  9,
        25, 49, 59,  1, 40, 34,
        24, 56, 18, 17,  0, 50,
        51, 58, 57, 48, 10, 33,
        12, 22, 29, 44, 62, 61,
        37, 20, 30, 11, 13, 54,
        19, 46, 28, 53,  5, 14,
         3,  4, 38, 52, 45, 21
    },
    { // Subkey 6
        51, 56, 10,  0, 25, 58,
         9, 33, 43, 50, 24, 18,
         8, 40,  2,  1, 49, 34,
        35, 42, 41, 32, 59, 17,
        27,  6, 13, 28, 46, 45,
        21,  4, 14, 62, 60, 38,
         3, 30, 12, 37, 52, 61,
        54, 19, 22, 36, 29,  5
    },
    { // Subkey 7
        35, 40, 59, 49,  9, 42,
        58, 17, 56, 34,  8,  2,
        57, 24, 51, 50, 33, 18,
        48, 26, 25, 16, 43,  1,
        11, 53, 60, 12, 30, 29,
         5, 19, 61, 46, 44, 22,
        54, 14, 27, 21, 36, 45,
        38,  3,  6, 20, 13, 52
    },
    { // Subkey 8
        56, 32, 51, 41,  1, 34,
        50,  9, 48, 26,  0, 59,
        49, 16, 43, 42, 25, 10,
        40, 18, 17,  8, 35, 58,
         3, 45, 52,  4, 22, 21,
        60, 11, 53, 38, 36, 14,
        46,  6, 19, 13, 28, 37,
        30, 62, 61, 12,  5, 44
    },
    { // Subkey 9
        40, 16, 35, 25, 50, 18,
        34, 58, 32, 10, 49, 43,
        33,  0, 56, 26,  9, 59,
        24,  2,  1, 57, 48, 42,
        54, 29, 36, 19,  6,  5,
        44, 62, 37, 22, 20, 61,
        30, 53,  3, 60, 12, 21,
        14, 46, 45, 27, 52, 28
    },
    { // Subkey 10
        24,  0, 48,  9, 34,  2,
        18, 42, 16, 59, 33, 56,
        17, 49, 40, 10, 58, 43,
         8, 51, 50, 41, 32, 26,
        38, 13, 20,  3, 53, 52,
        28, 46, 21,  6,  4, 45,
        14, 37, 54, 44, 27,  5,
        61, 30, 29, 11, 36, 12
    },
    { // Subkey 11
         8, 49, 32, 58, 18, 51,
         2, 26,  0, 43, 17, 40,
         1, 33, 24, 59, 42, 56,
        57, 35, 34, 25, 16, 10,
        22, 60,  4, 54, 37, 36,
        12, 30,  5, 53, 19, 29,
        61, 21, 38, 28, 11, 52,
        45, 14, 13, 62, 20, 27
    },
    { // Subkey 12
        57, 33, 16, 42,  2, 35,
        51, 10, 49, 56,  1, 24,
        50, 17,  8, 43, 26, 40,
        41, 48, 18,  9,  0, 59,
         6, 44, 19, 38, 21, 20,
        27, 14, 52, 37,  3, 13,
        45,  5, 22, 12, 62, 36,
        29, 61, 60, 46,  4, 11
    },
    { // Subkey 13
        41, 17,  0, 26, 51, 48,
        35, 59, 33, 40, 50,  8,
        34,  1, 57, 56, 10, 24,
        25, 32,  2, 58, 49, 43,
        53, 28,  3, 22,  5,  4,
        11, 61, 36, 21, 54, 60,
        29, 52,  6, 27, 46, 20,
        13, 45, 44, 30, 19, 62
    },
    { // Subkey 14
        25,  1, 49, 10, 35, 32,
        48, 43, 17, 24, 34, 57,
        18, 50, 41, 40, 59,  8,
         9, 16, 51, 42, 33, 56,
        37, 12, 54,  6, 52, 19,
        62, 45, 20,  5, 38, 44,
        13, 36, 53, 11, 30,  4,
        60, 29, 28, 14,  3, 46
    },
    { // Subkey 15
        17, 58, 41,  2, 56, 24,
        40, 35,  9, 16, 26, 49,
        10, 42, 33, 32, 51,  0,
         1,  8, 43, 34, 25, 48,
        29,  4, 46, 61, 44, 11,
        54, 37, 12, 60, 30, 36,
         5, 28, 45,  3, 22, 27,
        52, 21, 20,  6, 62, 38
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

void print_uint64_block(uint64_t inputs[64]) {
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
void zip_64_bit(uint64_t input[64], uint64_t output[64]) {
    memset(output, 0, 64*8);
    for (int bitnum=0; bitnum<64; bitnum++) {
        for (int blocknum=0; blocknum<64; blocknum++) {
            output[bitnum] |= ((input[blocknum] << bitnum) & 0x8000000000000000LL) >> blocknum;
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

void des_feistel(const uint64_t block_bits[64], uint64_t key_bits[64], uint64_t output[32], int roundnum) {

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

void des_encrypt(uint64_t block_bits[64], uint64_t key_bits[64]) {

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

    // Unswitch block halves
    uint64_t final_block[64];
    for (int i=0; i<64; i++) {
        final_block[i] = block_bits[encrypt_output_order[i]];
    }

    // Permute results into output_bits
    for (int i=0; i<64; i++) {
        block_bits[i] = final_block[final_permutation[i]];
    }

}

int main() {
    uint64_t keys[64];
    uint64_t keys_raw[64] = {
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL,
        0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL, 0x0f1571c947d9e859LL
    };
    uint64_t plaintext[64];
    uint64_t plaintext_raw[64] = {
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL,
        0x0000000000000000LL, 0x02468aceeca86420LL, 0x0000000000000000LL, 0x0000000000000000LL
    };
    //uint64_t ciphertext[64];
    uint64_t ciphertext_raw[64];

    printf("Keys:\n");
    print_uint64_block(keys_raw);
    printf("\n");

    printf("Plaintext:\n");
    print_uint64_block(plaintext_raw);
    printf("\n");

    zip_64_bit(keys_raw, keys);
    zip_64_bit(plaintext_raw, plaintext);

    //for (unsigned int i=0; i<1000000; i++)
    {
        //if (i % 10000) { printf("%u\n", i); }
        des_encrypt(plaintext, keys);
    }

    zip_64_bit(plaintext, ciphertext_raw);

    printf("Ciphertext:\n");
    print_uint64_block(ciphertext_raw);

}
