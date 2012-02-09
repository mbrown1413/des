
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

if __name__ == "__main__":

    key = hex_to_bits(argv[1])
    for i in [63, 55, 47, 39, 31, 23, 15, 7]:
        key.pop(i)
    print bits_to_hex(key)
