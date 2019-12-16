import sys
import os.path

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../lib/"))
sys.path.append(lib_directory)

import bittools
from desconst import INITIAL_PERMUTATION, FINAL_PERMUTATION, EXPANSION, PERMUTATION, PERMUTED_CHOICE_1_LEFT, PERMUTED_CHOICE_1_RIGHT, PERMUTED_CHOICE_2, SBOXES, KEY_SHIFT_AMOUNTS

print_logs = True


def dsa_feistel(half_block, subkey):
    assert len(half_block) == 32
    assert len(subkey) == 48

    expansion_output = bittools.permute(half_block, EXPANSION)
    xor_output = bittools.xor(expansion_output, subkey)
    sbox_output = dsa_substitution_box(xor_output)
    permute_output = bittools.permute(sbox_output, PERMUTATION)

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
        outer_bits = bittools.bits_to_int(half_block[index+0], half_block[index+5])
        inner_bits = bittools.bits_to_int(
            half_block[index+1],
            half_block[index+2],
            half_block[index+3],
            half_block[index+4],
        )
        result += bittools.int_to_4_bits(lookup_table[outer_bits][inner_bits])

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
    key_left = bittools.permute(key, PERMUTED_CHOICE_1_LEFT)
    key_right = bittools.permute(key, PERMUTED_CHOICE_1_RIGHT)
    assert len(key_left) == 28
    assert len(key_right) == 28
    log("Generating Subkeys:")
    log("    Initial Key =", bits_to_pretty(key))
    log("    Permuting into Left and Right keys")
    log("    Left Half  =", bits_to_pretty(key_left))
    log("    Right Half =", bits_to_pretty(key_right))
    for i in xrange(nrounds):
        shift_amount = KEY_SHIFT_AMOUNTS[i]
        bittools.left_shift(key_left, shift_amount)
        bittools.left_shift(key_right, shift_amount)
        subkey = bittools.permute(key_left + key_right, PERMUTED_CHOICE_2)
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
    block = bittools.permute(block, INITIAL_PERMUTATION)
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
        right_block = bittools.xor(left_block, fiestel_out)
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
    encrypted = bittools.permute(right_block + left_block, FINAL_PERMUTATION)
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
        (bittools.bits_to_binary_string(bits, blocksize), bittools.bits_to_hex(bits))
    '''
    return "0x%s %s-bit" % \
        (bittools.bits_to_hex(bits), len(bits))
    '''
    '''
    return "%s (0x%s) %s-bit" % \
        (bittools.bits_to_binary_string(bits, blocksize), bittools.bits_to_hex(bits), len(bits))
    '''

def bytes_from_file(filename):
    """Returns groups of 64 bits from filename."""
    bit_rows = []
    with open(filename, "rb") as f:
        while True:
            byte = f.read(8)
            if byte == "":
                break
            bits = bittools.ascii_to_bits(byte)
            while len(bits) < 64:
                bits = bits + [0,0,0,0,0,0,0,0]
            bit_rows.append(bits)
    return bit_rows

def get_key(orig_key):
    key = bittools.hex_to_bits(orig_key)
    if len(key) == 56:
        for i in [7, 15, 23, 31, 39, 47, 55, 63]:
            key.insert(i, 0)
    if len(key) != 64:
        raise ValueError("Key " + orig_key + " Is not 64 chars when expanded")
    return key

def get_keys(key_string):
    """Returns 1 or 3 key depending if DES or 3DES Keying Option 1 or 2."""
    keys = []

    if len(key_string) % 16 == 0:
        subkey_length = 16
    elif len(key_string) % 14 == 0:
        subkey_length = 14
    else:
        raise ValueError('Expected key length for [%s] to be a multiple of 14 or 16, was %d' % (key_string, len(key_string)))
    i = 0
    while i + subkey_length <= len(key_string):
        keys.append(get_key(key_string[i:i+subkey_length]))
        i += subkey_length

    if len(keys) == 2:
        # 3DES Keying option 2. Key 3 = Key 1.
        keys.append(keys[0])

    return keys

if __name__ == "__main__":

    from optparse import OptionParser
    op = OptionParser(
        usage = "%prog [options] <plaintext|ciphertext> key",
        description = "Encrypt (default) or decrypt using DES.  plaintext, ciphertext and key must be 64 bits in hex.")
    op.add_option("-d", "--decrypt", dest="decrypt", action="store_true",
        default=False, help="Interpret the first argument as ciphertext and decrypt it.")
    op.add_option("-c", "--encrypt", dest="decrypt", action="store_false",
        default=False, help="Interpret the first argument as plaintext and encrypt it. (default)")
    op.add_option("-v", "--verbose", dest="verbose", action="store_true",
        default=False, help="Print details and intermediate steps of the DSA algorithm.")
    op.add_option("-a", "--ascii", dest="ascii", action="store_true",
        default=False, help="Convert input plaintext from ascii if encrypting, or convert resulting plaintext to ascii if decrypting.")
    op.add_option("-f", "--file", dest="file",
        default=False, help="Encrypts / decrypts the file into an .encrypted / .decrypted.")
    (options, args) = op.parse_args()

    if options.file:
        if len(args) != 1:
            raise ValueError("Expected 1 and only 1 arg in file mode!")
        keys = get_keys(args[0])
    else:
        if len(args) < 2:
            op.error("Not enough arguments")
        elif len(args) > 2:
            op.error("Too many arguments")
        keys = get_keys(args[1])
    if (options.decrypt):
        keys.reverse()

    # text is plaintext if encrypting or ciphertext if decrypting
    if options.file:
        text = bytes_from_file(options.file)
    else:
        if options.ascii and not options.decrypt:
            text = bittools.ascii_to_bits(args[0])
        else:
            try:
                text = bittools.hex_to_bits(args[0])
            except ValueError:
                op.error("ciphertext couldn't be converted from [%s]. Perhaps you want --ascii or --file mode?" % args[0])
        if len(text) != 64:
            if options.decrypt:
                op.error("ciphertext must be 16 hex digits")
            else:
                op.error("plaintext must be 16 hex digits (or 8 ascii letters if using -a/--ascii)")
        text = [text]

    print_logs = options.verbose

    for round in range(len(keys)):
        key = keys[round]
        if len(key) != 64:
            print key, len(key)
            op.error("key %s must be 16 hex digits" % key)

        if round % 2 == 0:
            decrypt = options.decrypt
        else:
            # 3DES is EDE / DED, so round 2 is opposite.
            decrypt = not options.decrypt

        result = []
        for t in text:
            if decrypt:
                result += dsa_decrypt(t, key)
            else:
                result += dsa_encrypt(t, key)

        if options.file:
            filename = options.file + '.' + str(round) + '.'
            if decrypt:
                filename += 'decrypted'
            else:
                filename += 'encrypted'
            with open(filename, "wb") as f:
                f.write(bittools.bits_to_ascii(result))

        # Subsequent rounds are based on the result.
        text = []
        for i in range(0, len(result), 64):
            text.append(result[i:i+64])

    if options.ascii and decrypt:
        print bittools.bits_to_ascii(result)
    else:
        print bittools.bits_to_hex(result)
