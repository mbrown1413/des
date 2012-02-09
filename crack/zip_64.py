
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

    bits = hex_to_bits(argv[1])

    zipped = zip(*(bits for i in xrange(64)))

    print "        // Zipped 0x%s 64 times" % argv[1]

    width = 4
    for i, item in enumerate(zipped):
        if i%width == 0:
            print "       ",
        if i == 63:
            print "0x%sLL" % bits_to_hex(item),
        else:
            print "0x%sLL," % bits_to_hex(item),
        if i%width == width-1:
            print
