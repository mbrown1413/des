
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sbox.h"  // s-boxes: s0 to s7

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

void print_uint64_block(uint64_t inputs[64]) {
    for (int inputnum=0; inputnum<64; inputnum++) {
        printf("0x%016lx", inputs[inputnum]);
        if (inputnum == 63) {
            printf("\n");
        } else if (inputnum%8 == 7 && inputnum != 0) {
            printf(",\n");
        } else {
            printf(", ");
        }
    }
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
