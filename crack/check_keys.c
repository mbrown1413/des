
/*
 * Ideas originally taken from this research paper by Eli Biham:
 *     "A Fast New DES Implementation in Software"
 * Specifically, Biham pointed out that 64 encryptions can be done in
 * parallel on 64 bit machines, and S-Boxes can be calculated with
 * simple gate logic.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// Define plaintext_zipped, ciphertext_zipped, and NUM_CHUNK_BITS
#include "input.h"

#include "sbox.h"  // s-boxes: s0 to s7

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

/*
 * Take 64 integers of length 64 and put the ith bit of input[j] into
 * the jth bit of output[i].  Think of this as writing every single bit
 * into a 64x64 matrix, then transposing that matrix.  Consequently,
 * function is its own inverse.
 */
inline static void zip_64_bit(const uint64_t input[64], uint64_t output[64]) {
    memset(output, 0, 64*8);
    for (int bitnum=0; bitnum<64; bitnum++) {
        for (int blocknum=0; blocknum<64; blocknum++) {
            output[bitnum] |= ((input[blocknum] << bitnum) & 0x8000000000000000LL) >> blocknum;
        }
    }
}

static void des_feistel(const uint64_t block_bits[64], const uint64_t key_bits[56], uint64_t output[32], const int roundnum) {

    const unsigned char* key_bit_order = key_bit_orders[roundnum];

    // Either 0 (left block) or 32 (right block) depending on the round
    #define BLOCK_START(roundnum) ( (roundnum+1)%2 * 32 )

    // Gives the feistel expansion of the left or right block (depending on the
    // round).  Rather than giving an integer from 0-47 for each expansion
    // output bit, the sbox that the input is needed for is given.
    //   snum - An integer from 0-7 specifying which sbox to get the inputs of.
    //   i - An integer from 0-5 specifying which input from the sbox to get.
    #define EXPANDED(snum, i, roundnum) ( block_bits[(snum*4 + (i+31)%32) % 32 + BLOCK_START(roundnum)] )

    // Gets the key bit i from round roundnum.
    #define KEY_BIT(roundnum, i) ( key_bits[key_bit_order[i]] )

    // Call an sbox
    #define S(snum) \
        s ## snum ( \
            EXPANDED(snum, 0, roundnum) ^ KEY_BIT(roundnum, snum*6 + 0), \
            EXPANDED(snum, 1, roundnum) ^ KEY_BIT(roundnum, snum*6 + 1), \
            EXPANDED(snum, 2, roundnum) ^ KEY_BIT(roundnum, snum*6 + 2), \
            EXPANDED(snum, 3, roundnum) ^ KEY_BIT(roundnum, snum*6 + 3), \
            EXPANDED(snum, 4, roundnum) ^ KEY_BIT(roundnum, snum*6 + 4), \
            EXPANDED(snum, 5, roundnum) ^ KEY_BIT(roundnum, snum*6 + 5), \
            &output[feistel_output_order[snum*4 + 0]], \
            &output[feistel_output_order[snum*4 + 1]], \
            &output[feistel_output_order[snum*4 + 2]], \
            &output[feistel_output_order[snum*4 + 3]] \
        );

    S(0);
    S(1);
    S(2);
    S(3);
    S(4);
    S(5);
    S(6);
    S(7);

    #undef BLOCK_STORT
    #undef EXPANDED
    #undef KEY_BIT
    #undef S

}

inline static void des_decrypt(uint64_t ciphertext_bits[64], const uint64_t key_bits[56]) {

    static uint64_t feistel_output[32];
    #define ROUND(roundnum) \
        des_feistel(ciphertext_bits, key_bits, feistel_output, roundnum); \
        for (int i=0; i<32; i++) { \
            ciphertext_bits[i + (roundnum%2 * 32)] ^= feistel_output[i]; \
        }

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);
    ROUND(10);
    ROUND(11);
    ROUND(12);
    ROUND(13);
    ROUND(14);
    ROUND(15);

    #undef ROUND

}

/*
 * Compares two zipped inputs.  Return a uint64_t in which each 0 represents a
 * match for that position.
 */
inline static uint64_t compare(const uint64_t a[64], const uint64_t b[64]) {
    uint64_t result = 0LL;
    for (int i=0; i<64; i++) {
        result |= a[i] ^ b[i];
        if (result == 0xffffffffffffffff) {
            return result;
        }

    }
    return result;
}

static void check_key_64(const uint64_t plaintext_zipped[64], const uint64_t ciphertext_zipped[64], const uint64_t keys_zipped[56]) {
    static uint64_t temp[64];

    //TODO: Try rearranging things so this memcpy isn't needed.
    memcpy(temp, ciphertext_zipped, 64*8);

    des_decrypt(temp, keys_zipped);
    // temp is now plaintext zipped

    uint64_t comparison = compare(temp, plaintext_zipped);
    if (comparison != 0xffffffffffffffffLL) {

        // Print matched keys
        zip_64_bit(keys_zipped, temp);
        for (int i=0; i<64; i++) {
            if (~comparison & 0x8000000000000000LL) {
                printf("0x%014lx\n", temp[i]>>8);
            }
            comparison <<= 1;
        }

    }
}

static void check_key_chunk(const uint64_t plaintext_zipped[64], const uint64_t ciphertext_zipped[64], uint64_t keys_zipped[56]) {
    for (int i=0; i<pow(2, (NUM_CHUNK_BITS-6)); i++) {

        check_key_64(plaintext_zipped, ciphertext_zipped, keys_zipped);

        // Increment keys_zipped
        for (int j=56-NUM_CHUNK_BITS; ; j++) {
            keys_zipped[j] ^= 0xffffffffffffffffLL;
            if (keys_zipped[j]) {
                break;
            }
        }

    }
}

int main(int argc, char** argv) {

    // Initialize keys to 0 to 63 (zipped).  The search starting point is
    // added based on argv[1].  Then after every round of 64 decryptions, the
    // keys are all incremented by 64.
    static uint64_t keys_zipped[56] = {
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
        return -1;
    }
    for (int i=0; i<56-NUM_CHUNK_BITS; i++) {
        keys_zipped[i] = (argv[1][i]-48) * 0xffffffffffffffffLL;
    }

    check_key_chunk(plaintext_zipped, ciphertext_zipped, keys_zipped);

}
