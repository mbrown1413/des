
from copy import copy

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

def xor(block_a, block_b):
    result = []
    for item_a, item_b in zip(block_a, block_b):
        if item_a == item_b:
            result.append(0)
        else:
            result.append(1)
    return result

def left_shift(block, amount=1):
    for i in range(amount):
        block.append(block.pop(0))

def bits_to_int(*bits):
    string = ''
    for bit in bits:
        string += str(bit)
    return int(string, 2)

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
    for i in range(len(bits) % 4):
        bits.insert(0, 0)

    # Convert each 4-bit block to hex
    for i in range(0, len(bits), 4):
        digit = hex(int(''.join(map(str, bits[i:i+4])), 2))[2:];
        result.append(digit)

    return ''.join(result)

def bits_to_binary_string(bits, blocksize=4):
    bits = copy(bits)
    result = []

    # Pad to a multiple of blocksize bits
    for i in range(len(bits) % blocksize):
        bits.insert(0, 0)

    for i in range(0, len(bits), blocksize):
        block_str = ''.join(map(str, bits[i:i+blocksize]))
        result.append(block_str)

    return ' '.join(result)

def ascii_to_bits(string):
    result = []
    for char in string:
        char_int = ord(char)
        result.extend(int_to_4_bits((char_int & 0xF0) >> 4))
        result.extend(int_to_4_bits(char_int & 0x0F))
    return result

def bits_to_ascii(bits):
    return hex_to_ascii(bits_to_hex(bits))

def hex_to_ascii(hex_string):
    assert len(hex_string) % 2 == 0  # Length divisible by 2
    result = []
    for i in range(0, len(hex_string), 2):
        first_nibble = int(hex_string[i], 16)
        second_nibble = int(hex_string[i+1], 16)
        byte = 16*first_nibble + second_nibble
        result.append(chr(byte))
    return ''.join(result)

def permute(block, permutation_table):
    assert len(block) > max(permutation_table)-1
    result = []
    for position in permutation_table:
        result.append(block[position-1])  # -1 since tables are 1-indexed
    return result

def invert_permutation(p):
    result = []
    for i in range(len(p)):
        result.append(p.index(i+1)+1)  # +1's since tables are 1-indexed
    return result
