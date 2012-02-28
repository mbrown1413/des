
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
    (options, args) = op.parse_args()

    if len(args) < 2:
        op.error("Not enough arguments")
    elif len(args) > 2:
        op.error("Too many arguments")
    key = bittools.hex_to_bits(args[1])

    # text is plaintext if encrypting or ciphertext if decrypting
    if options.ascii and not options.decrypt:
        text = bittools.ascii_to_bits(args[0])
    else:
        text = bittools.hex_to_bits(args[0])
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
        print bittools.bits_to_ascii(result)
    else:
        print bittools.bits_to_hex(result)
