
from itertools import izip, imap
from copy import copy

print_logs = True

# Applied once at the beginning of the algorithm.
INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Inverse of INITIAL_PERMUTATION.  Applied once at the end of the algorithm.
FINAL_PERMUTATION = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]

# Applied to the half-block at the beginning of the Fiestel function.
EXPANSION = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# Applied at the end of the Feistel function.
PERMUTATION = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# Converts from full 64-bit key to two key halves: left and right.  Only 48
# bits from the original key are used.
PERMUTED_CHOICE_1_LEFT = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
]
PERMUTED_CHOICE_1_RIGHT = [
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# Converts the shifted right and left key halves (concatenated together) into
# the subkey for the round (input into Feistel function).
PERMUTED_CHOICE_2 = [
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

# S-Boxes
# SBOX[outer 2 bits][inner 4 bits]
# Each value represents 4 bits that the 6-bit input is mapped to.
SBOX_1 = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
]
SBOX_2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]
SBOX_3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
]
SBOX_4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]
SBOX_5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
]
SBOX_6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]
SBOX_7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
]
SBOX_8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
SBOXES = [SBOX_1, SBOX_2, SBOX_3, SBOX_4, SBOX_5, SBOX_6, SBOX_7, SBOX_8];

# How much the left and right key halves are shifted every round.
KEY_SHIFT_AMOUNTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

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
    for item_a, item_b in izip(block_a, block_b):
        if item_a == item_b:
            result.append(0)
        else:
            result.append(1)
    return result

def left_shift(block, amount=1):
    for i in xrange(amount):
        block.append(block.pop(0))

def permute(block, permutation_table):
    assert len(block) > max(permutation_table)-1
    result = []
    for position in permutation_table:
        result.append(block[position-1])  # -1 since tables are 1-indexed
    return result

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
    for i in xrange(len(bits) % 4):
        bits.insert(0, 0)

    # Convert each 4-bit block to hex
    for i in xrange(0, len(bits), 4):
        digit = hex(int(''.join(imap(str, bits[i:i+4])), 2))[2:];
        result.append(digit)

    return ''.join(result)

def bits_to_binary_string(bits, blocksize=4):
    bits = copy(bits)
    result = []

    # Pad to a multiple of blocksize bits
    for i in xrange(len(bits) % blocksize):
        bits.insert(0, 0)

    for i in xrange(0, len(bits), blocksize):
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
    for i in xrange(0, len(hex_string), 2):
        first_nibble = int(hex_string[i], 16)
        second_nibble = int(hex_string[i+1], 16)
        byte = 16*first_nibble + second_nibble
        result.append(chr(byte))
    return ''.join(result)


def dsa_feistel(half_block, subkey):
    assert len(half_block) == 32
    assert len(subkey) == 48

    expansion_output = permute(half_block, EXPANSION)
    xor_output = xor(expansion_output, subkey)
    sbox_output = dsa_substitution_box(xor_output)
    permute_output = permute(sbox_output, PERMUTATION)

    log("    Feistel(Right Block, Subkey):");
    log("        Expand(Right Block)       =", bits_to_pretty(expansion_output))
    log("        Expanded(...) XOR Subkey  =", bits_to_pretty(xor_output, 6))
    log("        S-Box(...)                =", bits_to_pretty(sbox_output))
    log("        Permutation(...) (output) =", bits_to_pretty(permute_output))

    return permute_output

def dsa_substitution_box(half_block):
    assert len(half_block) == 48
    result = []

    # group_num represents which 6-bit group (out of 8) we are processing.
    for group_num in xrange(0,8):
        index = group_num * 6  # Index into half_block of start of group
        lookup_table = SBOXES[group_num]
        outer_bits = bits_to_int(half_block[index+0], half_block[index+5])
        inner_bits = bits_to_int(
            half_block[index+1],
            half_block[index+2],
            half_block[index+3],
            half_block[index+4],
        )
        result += int_to_4_bits(lookup_table[outer_bits][inner_bits])

    return result

def dsa_decrypt(block, key):
    return dsa_encrypt(block, key, decrypt=True)

def dsa_encrypt(block, key, decrypt=False):
    nrounds = 16
    assert len(block) == 64
    assert len(key) == 64

    if decrypt:
        log("Decrypting:", bits_to_pretty(block))
    else:
        log("Encrypting:", bits_to_pretty(block))

    # Generate subkeys
    subkeys = []
    key_left = permute(key, PERMUTED_CHOICE_1_LEFT)
    key_right = permute(key, PERMUTED_CHOICE_1_RIGHT)
    assert len(key_left) == 28
    assert len(key_right) == 28
    log("Generating Subkeys:")
    log("    Initial Key =", bits_to_pretty(key))
    log("    Permuting into Left and Right keys")
    log("    Left Half  =", bits_to_pretty(key_left))
    log("    Right Half =", bits_to_pretty(key_right))
    for i in xrange(nrounds):
        shift_amount = KEY_SHIFT_AMOUNTS[i]
        left_shift(key_left, shift_amount)
        left_shift(key_right, shift_amount)
        subkey = permute(key_left + key_right, PERMUTED_CHOICE_2)
        subkeys.append(subkey)

        log("")
        log("Subkey %s:" % i)
        log("    Shifting key halves to the left by %s bits" % shift_amount)
        log("    Left Half  =", bits_to_pretty(key_left))
        log("    Right Half =", bits_to_pretty(key_right))
        log("    Permuting Left and Right key into subkey")
        log("    Subkey =", bits_to_pretty(subkey))

    # Apply subkeys in reverse order if decrypting
    log("")
    if decrypt:
        log("Reversing order of subkeys")
        subkeys = subkeys[::-1]

    # Initial Permutation
    block = permute(block, INITIAL_PERMUTATION)
    log("Initial Permutation:", bits_to_pretty(block))
    log("")

    # Rounds
    left_block = block[0:32]
    right_block = block[32:]
    for i in xrange(nrounds):

        log("Round %s:" % i)
        log("    Input:")
        log("        Subkey      =", bits_to_pretty(subkeys[i]))
        log("        Left Block  =", bits_to_pretty(left_block))
        log("        Right Block =", bits_to_pretty(right_block))

        tmp = right_block
        fiestel_out = dsa_feistel(right_block, subkeys[i])
        right_block = xor(left_block, fiestel_out)
        left_block = tmp

        log("    Output:")
        log("        Left Block = Left Block XOR Feistel(...)")
        log("                   =", bits_to_pretty(right_block))
        log("        Right Block (Unchanged)")
        if i == 15:
            log("    DO NOT SWITCH right and left block after the last round")
        else:
            log("    Left and Right blocks are switched and input into next round.")
        log("")

    # Final Permutation
    # right and left are switched here because the final round does not switch
    # them.  Here we just switch them back.
    encrypted = permute(right_block + left_block, FINAL_PERMUTATION)
    log("Result after all rounds = Left Block + Right Block")
    log("                        =", bits_to_pretty(right_block+left_block))
    log("After Final Permutation =", bits_to_pretty(encrypted))
    log("")

    return encrypted

def log(*text):
    if print_logs:
        for string in text:
            print string,
        print

def bits_to_pretty(bits, blocksize=8):
    return "%s (0x%s)" % \
        (bits_to_binary_string(bits, blocksize), bits_to_hex(bits))
    '''
    return "0x%s %s-bit" % \
        (bits_to_hex(bits), len(bits))
    '''
    '''
    return "%s (0x%s) %s-bit" % \
        (bits_to_binary_string(bits, blocksize), bits_to_hex(bits), len(bits))
    '''

if __name__ == "__main__":

    from optparse import OptionParser
    op = OptionParser(
        usage = "%prog [options] <plaintext|ciphertext> <key>",
        description = "Encrypt or decrypt using DES.  plaintext, ciphertext and key must be in hex.")
    op.add_option("-d", "--decrypt", dest="decrypt", action="store_true",
        default=False, help="Interpret the first argument as ciphertext and decrypt it.")
    op.add_option("-c", "--encrypt", dest="decrypt", action="store_false",
        default=False, help="Interpret the first argument as plaintext and encrypt it. (default)")
    op.add_option("-v", "--verbose", dest="verbose", action="store_true",
        default=False, help="Print details and intermediate steps of the DSA algorithm.")
    op.add_option("-a", "--ascii", dest="ascii", action="store_true",
        default=False, help="Convert plaintext from ascii before encrypting, or convert plaintext to ascii after decrypting.")
    (options, args) = op.parse_args()

    if len(args) < 2:
        op.error("Not enough arguments")
    elif len(args) > 2:
        op.error("Too many arguments")
    key = hex_to_bits(args[1])

    # text is plaintext if encrypting or ciphertext if decrypting
    if options.ascii and not options.decrypt:
        text = ascii_to_bits(args[0])
    else:
        text = hex_to_bits(args[0])
    if len(text) != 64:
        if options.decrypt:
            op.error("ciphertext must be 16 hex digits")
        else:
            op.error("plaintext must be 16 hex digits (or 8 ascii letters if using -a/--ascii)")
    if len(key) != 64:
        print key, len(key)
        op.error("key must be 16 hex digits")

    if options.verbose:
        print_logs = True
    else:
        print_logs = False

    if options.decrypt:
        result = dsa_decrypt(text, key)
    else:
        result = dsa_encrypt(text, key)

    if options.ascii and options.decrypt:
        print bits_to_ascii(result)
    else:
        print bits_to_hex(result)
