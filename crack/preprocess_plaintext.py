
from sys import argv
from copy import copy
from itertools import imap

# ith list contains binary representing i.
BINARY_4_BIT_LOOKUP = [
    [0, 0, 0, 0],
    [0, 0, 0, 1],
    [0, 0, 1, 0],
    [0, 0, 1, 1],
    [0, 1, 0, 0],
    [0, 1, 0, 1],
    [0, 1, 1, 0],
    [0, 1, 1, 1],
    [1, 0, 0, 0],
    [1, 0, 0, 1],
    [1, 0, 1, 0],
    [1, 0, 1, 1],
    [1, 1, 0, 0],
    [1, 1, 0, 1],
    [1, 1, 1, 0],
    [1, 1, 1, 1],
]

def int_to_4_bits(num):
    assert num >= 0 and num <= 15
    return BINARY_4_BIT_LOOKUP[num]

def hex_to_bits(hex_string):
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    result = []
    for digit in hex_string:
        num = int(digit, 16)
        result.extend(int_to_4_bits(num))
    return result

def bits_to_hex(bits):
    bits = copy(bits)
    result = []

    # Pad to a multiple of 4 bits
    for i in xrange(len(bits) % 4):
        bits.insert(0, 0)

    # Convert each 4-bit block to hex
    for i in xrange(0, len(bits), 4):
        digit = hex(int(''.join(imap(str, bits[i:i+4])), 2))[2:];
        result.append(digit)

    return ''.join(result)

output_order = [
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,

    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

final_permutation = [
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
    32, 0, 40,  8, 48, 16, 56, 24
]

def revert_permutation(p):
    result = []
    for i in xrange(len(p)):
        result.append(p.index(i))
    return result

def permute(block, permutation_table):
    assert len(block) > max(permutation_table)-1
    result = []
    for position in permutation_table:
        result.append(block[position])
    return result

if __name__ == "__main__":
    plaintext = hex_to_bits(argv[1])
    processed = permute(
        permute(plaintext, revert_permutation(final_permutation)),
        revert_permutation(output_order)
    )
    print bits_to_hex(processed)
