
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// All of the numbers in the permutation tables are 0-indexed.  However, most
// DES references show them 1-indexed!

// Applied once at the beginning of the algorithm.
static const unsigned char initial_permutation_left[32] = {
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};
static const unsigned char initial_permutation_right[32] = {
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
};

// Inverse of initial_permutation.  Applied once at the end of the algorithm.
static const unsigned char final_permutation[64] = {
    7, 39, 15, 47, 23, 55, 31, 63,
    6, 38, 14, 46, 22, 54, 30, 62,
    5, 37, 13, 45, 21, 53, 29, 61,
    4, 36, 12, 44, 20, 52, 28, 60,
    3, 35, 11, 43, 19, 51, 27, 59,
    2, 34, 10, 42, 18, 50, 26, 58,
    1, 33,  9, 41, 17, 49, 25, 57,
    0, 32,  8, 40, 16, 48, 24, 56
};

// Applied to the half-block at the beginning of the Fiestel function.
static const unsigned char expansion_permutation[48] = {
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
};

// Applied at the end of the Feistel function.
static const unsigned char feistel_end_permutation[32] = {
    15,  6, 19, 20, 28, 11, 27, 16,
     0, 14, 22, 25,  4, 17, 30,  9,
     1,  7, 23, 13, 31, 26,  2,  8,
    18, 12, 29,  5, 21, 10,  3, 24
};

// Converts from full 64-bit key to two key halves: left and right.  Only 48
// bits from the original key are used.
static const unsigned char permuted_choice_1[56] = {
    // Left Half
    56, 48, 40, 32, 24, 16,  8,
     0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,
    18, 10,  2, 59, 51, 43, 35,
    // Right Half
    62, 54, 46, 38, 30, 22, 14,
     6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,
    20, 12,  4, 27, 19, 11,  3
};

// Converts the shifted right and left key halves (concatenated together) into
// the subkey for the round (input into Feistel function).
static const unsigned char permuted_choice_2[48] = {
    13, 16, 10, 23,  0,  4,  2, 27,
    14,  5, 20,  9, 22, 18, 11,  3,
    25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39,
    50, 44, 32, 47, 43, 48, 38, 55,
    33, 52, 45, 41, 49, 35, 28, 31
};

// S-Boxes
// Each value represents 4 bits that the 6-bit input is mapped to.
//
// This is in a different order than you would normally find it in an DES
// reference, so that the sbox lookup is reduced to a single lookup on the
// input byte.
static const unsigned char sbox_0[64] = {
    14,  0,  4, 15, 13,  7,  1,  4,
     2, 14, 15,  2, 11, 13,  8,  1,
     3, 10, 10,  6,  6, 12, 12, 11,
     5,  9,  9,  5,  0,  3,  7,  8,
     4, 15,  1, 12, 14,  8,  8,  2,
    13,  4,  6,  9,  2,  1, 11,  7,
    15,  5, 12, 11,  9,  3,  7, 14,
     3, 10, 10,  0,  5,  6,  0, 13
};
static const unsigned char sbox_1[64] = {
    15,  3,  1, 13,  8,  4, 14,  7,
     6, 15, 11,  2,  3,  8,  4, 14,
     9, 12,  7,  0,  2,  1, 13, 10,
    12,  6,  0,  9,  5, 11, 10,  5,
     0, 13, 14,  8,  7, 10, 11,  1,
    10,  3,  4, 15, 13,  4,  1,  2,
     5, 11,  8,  6, 12,  7,  6, 12,
     9,  0,  3,  5,  2, 14, 15,  9
};
static const unsigned char sbox_2[64] = {
    10, 13,  0,  7,  9,  0, 14,  9,
     6,  3,  3,  4, 15,  6,  5, 10,
     1,  2, 13,  8, 12,  5,  7, 14,
    11, 12,  4, 11,  2, 15,  8,  1,
    13,  1,  6, 10,  4, 13,  9,  0,
     8,  6, 15,  9,  3,  8,  0,  7,
    11,  4,  1, 15,  2, 14, 12,  3,
     5, 11, 10,  5, 14,  2,  7, 12
};
static const unsigned char sbox_3[64] = {
     7, 13, 13,  8, 14, 11,  3,  5,
     0,  6,  6, 15,  9,  0, 10,  3,
     1,  4,  2,  7,  8,  2,  5, 12,
    11,  1, 12, 10,  4, 14, 15,  9,
    10,  3,  6, 15,  9,  0,  0,  6,
    12, 10, 11,  1,  7, 13, 13,  8,
    15,  9,  1,  4,  3,  5, 14, 11,
     5, 12,  2,  7,  8,  2,  4, 14
};
static const unsigned char sbox_4[64] = {
     2, 14, 12, 11,  4,  2,  1, 12,
     7,  4, 10,  7, 11, 13,  6,  1,
     8,  5,  5,  0,  3, 15, 15, 10,
    13,  3,  0,  9, 14,  8,  9,  6,
     4, 11,  2,  8,  1, 12, 11,  7,
    10,  1, 13, 14,  7,  2,  8, 13,
    15,  6,  9, 15, 12,  0,  5,  9,
     6, 10,  3,  4,  0,  5, 14,  3
};
static const unsigned char sbox_5[64] = {
    12, 10,  1, 15, 10,  4, 15,  2,
     9,  7,  2, 12,  6,  9,  8,  5,
     0,  6, 13,  1,  3, 13,  4, 14,
    14,  0,  7, 11,  5,  3, 11,  8,
     9,  4, 14,  3, 15,  2,  5, 12,
     2,  9,  8,  5, 12, 15,  3, 10,
     7, 11,  0, 14,  4,  1, 10,  7,
     1,  6, 13,  0, 11,  8,  6, 13
};
static const unsigned char sbox_6[64] = {
     4, 13, 11,  0,  2, 11, 14,  7,
    15,  4,  0,  9,  8,  1, 13, 10,
     3, 14, 12,  3,  9,  5,  7, 12,
     5,  2, 10, 15,  6,  8,  1,  6,
     1,  6,  4, 11, 11, 13, 13,  8,
    12,  1,  3,  4,  7, 10, 14,  7,
    10,  9, 15,  5,  6,  0,  8, 15,
     0, 14,  5,  2,  9,  3,  2, 12
};
static const unsigned char sbox_7[64] = {
    13,  1,  2, 15,  8, 13,  4,  8,
     6, 10, 15,  3, 11,  7,  1,  4,
    10, 12,  9,  5,  3,  6, 14, 11,
     5,  0,  0, 14, 12,  9,  7,  2,
     7,  2, 11,  1,  4, 14,  1,  7,
     9,  4, 12, 10, 14,  8,  2, 13,
     0, 15,  6, 12, 10,  9, 13,  0,
    15,  3,  3,  5,  5,  6,  8, 11
};

// How much the left and right key halves are shifted every round.
static const unsigned char key_shift_amounts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

char* bin_to_string(const unsigned char input[], int nbytes) {
    #define MAX_BYTES 64
    static char output[MAX_BYTES*2 + 3];
    char* output_ptr = output;
    if (nbytes > MAX_BYTES) {
        fprintf(stderr, "ERROR: bin_to_string supports up to %d bytes.  %d bytes given.\n", MAX_BYTES, nbytes);
    }
    sprintf(output, "0x");
    output_ptr += 2;
    for (int i=0; i<nbytes; i++) {
        sprintf(output_ptr, "%02x", input[i]);
        output_ptr += 2;
    }
    return output;
    #undef MAX_BYTES
}

void print_hex(unsigned char input[], int nbytes) {
    printf("%s", bin_to_string(input, nbytes));
}

/*
unsigned char* hexstr_to_bin(unsigned char* input, unsigned char length) {
    //TODO
}
*/

void xor(const unsigned char* block_a, const unsigned char* block_b, unsigned char* output, unsigned char nbytes) {
    for (int i=0; i<nbytes; i++) {
        output[i] = block_a[i] ^ block_b[i];
    }
}

void permute(const unsigned char* input, const unsigned char* table, unsigned char* output, unsigned char nbytes) {
    const unsigned char* table_cell = table;

    for (int i=0; i<nbytes; i++) {
        unsigned char result_byte = 0x00;
        for (int j=0; j<8; j++) {

            // Retrieve result_bit from lookup and store in result_byte
            unsigned char bit_pos = *table_cell % 8;
            unsigned char mask = 0x80 >> bit_pos;
            unsigned char result_bit = (input[*table_cell/8] & mask) << bit_pos;
            result_byte |= result_bit >> j;

            table_cell++;
        }
        output[i] = result_byte;
    }
}

/*
 * The key given is both halves of the key.  We shift each half of the key to
 * the left separately.
 */
void dsa_key_shift(unsigned char key[7], unsigned char output[7], unsigned char amount) {
    unsigned char mask;

    // Shift bytes circularly.
    // Last byte will be handled specially.
    for (int i=0; i<7; i++) {
        output[i] = (key[i] << amount) | (key[i+1] >> (8-amount));
    }

    // Middle byte straddles the two key halves.  Set the right 1 or 2 bits of
    // the left key.
    if (amount == 1) {
        mask = 0xEF;
    } else {
        mask = 0xCF;
    }
    output[3] &= mask;  // Zero the bits out
    output[3] |= (key[0] >> (4-amount)) & ~mask;  // Add left 1 or 2 bits

    // Last bit must borrow from left side of right key.
    if (amount == 1) {
        mask = 0x01;
    } else {
        mask = 0x03;
    }
    output[6] = (key[6] << amount) | ((key[3] >> (4-amount)) & mask);

}

void dsa_substitution_box(const unsigned char input[6], unsigned char output[4]) {
    unsigned char input_byte;

    // S-Box 0
    input_byte = (input[0] & 0xFC)>>2;
    output[0] = sbox_0[input_byte] << 4;

    // S-Box 1
    input_byte = ((input[0] & 0x03)<<4) + ((input[1] & 0xF0)>>4);
    output[0] = output[0] | sbox_1[input_byte];

    // S-Box 2
    input_byte = ((input[1] & 0x0F)<<2) + ((input[2] & 0xC0)>>6);
    output[1] = sbox_2[input_byte] << 4;

    // S-Box 3
    input_byte = (input[2] & 0x3F);
    output[1] = output[1] | sbox_3[input_byte];

    // S-Box 4
    input_byte = (input[3] & 0xFC)>>2;
    output[2] = sbox_4[input_byte] << 4;

    // S-Box 5
    input_byte = ((input[3] & 0x03)<<4) + ((input[4] & 0xF0)>>4);
    output[2] = output[2] | sbox_5[input_byte];

    // S-Box 6
    input_byte = ((input[4] & 0x0F)<<2) + ((input[5] & 0xC0)>>6);
    output[3] = sbox_6[input_byte] << 4;

    // S-Box 7
    input_byte = (input[5] & 0x3F);
    output[3] = output[3] | sbox_7[input_byte];

}

void dsa_feistel(const unsigned char input[4], const unsigned char subkey[6], unsigned char output[4]) {
    unsigned char expanded[6];
    unsigned char sbox_output[4];

    // TODO: Can expansion be done faster than a dumb permutation algorithm?
    permute(input, expansion_permutation, expanded, 6);
    // TODO: Can xor and sbox be combined?
    xor(expanded, subkey, expanded, 6);
    dsa_substitution_box(expanded, sbox_output);
    permute(sbox_output, feistel_end_permutation, output, 4);

}

void dsa_encrypt(unsigned char block[8], unsigned char key[8], unsigned char output[8]) {
    // TODO: This whole program could probably benifit from using larger
    //       datatypes that char.
    unsigned char key_halves_a[7];  // left key + right key
    unsigned char key_halves_b[7];  // Also left key + right key
    unsigned char subkey[6];
    unsigned char fiestel_output[4];

    // left_block and right_block must be beside eachother in memory, so the
    // memory is allocated in one chunk and the left and right block use 4
    // bytes each.
    unsigned char* left_block = malloc(8);
    unsigned char* right_block = &left_block[4];

    permute(block, initial_permutation_left, left_block, 4);
    permute(block, initial_permutation_right, right_block, 4);

    // TODO: Pre shift permuted_choice_1 to eliminate left shift to generate
    //       the first subkey.  Or maybe even have a lookup table for each
    //       subkey.
    permute(key, permuted_choice_1, key_halves_a, 7);

    // Calculate 16 Rounds
    // Each loop iteration calculates two rounds.  This way there are no
    // memcoppies at the end of each round to for example switch right_block
    // and left_block.
    for (int i=0; i<16; i+=2) {

        // Generate key (even round)
        dsa_key_shift(key_halves_a, key_halves_b, key_shift_amounts[i]);
        permute(key_halves_b, permuted_choice_2, subkey, 6);

        // Round calculation (even round)
        dsa_feistel(right_block, subkey, fiestel_output);
        xor(fiestel_output, left_block, left_block, 4);

        // Generate key (odd round)
        dsa_key_shift(key_halves_b, key_halves_a, key_shift_amounts[i+1]);
        permute(key_halves_a, permuted_choice_2, subkey, 6);

        // Round calculation (odd round)
        dsa_feistel(left_block, subkey, fiestel_output);
        xor(fiestel_output, right_block, right_block, 4);

    }

    // Switch back left and right block
    // This step is skipped, since the final permutation has been modified to
    // account for it.

    permute(left_block, final_permutation, output, 8);

}

int main() {
    //unsigned char plaintext[8] = {0x6d, 0x73, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x33};
    unsigned char plaintext[8] = {0x02, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20};
    unsigned char key[8] = {0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59};
    unsigned char ciphertext[8];

    for (int i=0; i<1000000; i++) {
        dsa_encrypt(plaintext, key, ciphertext);
    }

    printf("%s\n", bin_to_string(ciphertext, 8));

}
