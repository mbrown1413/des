
import os.path
import sys
from optparse import OptionParser

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

import bittools
import desconst

def preprocess_plaintext(bits):

    # Initial Permutation
    permuted = bittools.permute(bits, desconst.INITIAL_PERMUTATION)

    # Switch left and right half
    return permuted[32:64] + permuted[0:32]

def preprocess_ciphertext(bits):

    # Initial Permutation
    return bittools.permute(bits, desconst.INITIAL_PERMUTATION)

def zip_and_format(bits):
    result = ""

    zipped = zip(*(bits for i in range(64)))

    width = 4
    for i, item in enumerate(zipped):
        if i%width == 0:
            result += "    "
        result += "0x%sLL" % bittools.bits_to_hex(item)
        if i != 63:
            result += ","
        if i%width == width-1:
            result += "\n"
        else:
            result += " "

    return result

if __name__ == "__main__":

    op = OptionParser(
        usage="%prog <plaintext> <ciphertext> <num_chunk_bits>",
        description="Sets up the input for the keysearch by creating 'input.h'. "
        "plaintext and ciphertext must be 64 bits of hex (without the 0x "
        "prefix).  num_chunk_bits specifies the number of bits a single call to "
        "check_keys will search.  It must be between 6 and 56 inclusive.")
    (options, args) = op.parse_args()

    if len(args) < 3:
        op.error("Not enough arguments")
    elif len(args) > 3:
        op.error("Too many arguments")
    plaintext = bittools.hex_to_bits(args[0])
    ciphertext = bittools.hex_to_bits(args[1])
    try:
        num_chunk_bits = int(args[2])
    except ValueError:
        op.error("num_chunk_bits must be an integer between 6 and 56 inclusive")

    if len(plaintext) != 64:
        op.error("plaintext must be 16 hex digits")
    if len(ciphertext) != 64:
        op.error("ciphertext must be 16 hex digits")
    if num_chunk_bits < 6 or num_chunk_bits > 56:
        op.error("num_chunk_bits must be an integer between 6 and 56 inclusive")

    f = open("input.h", 'w')

    f.write("#define NUM_CHUNK_BITS %d\n\n" % num_chunk_bits)

    processed_plaintext = preprocess_plaintext(plaintext)
    f.write("static uint64_t plaintext_zipped[64] = {\n\n")
    f.write("    // Unprocessed plaintext: 0x%s\n" % args[0])
    f.write(zip_and_format(processed_plaintext))
    f.write("\n};\n\n")

    processed_ciphertext = preprocess_ciphertext(ciphertext)
    f.write("static uint64_t ciphertext_zipped[64] = {\n\n")
    f.write("    // Unprocessed ciphertext: 0x%s\n" % args[1])
    f.write(zip_and_format(processed_ciphertext))
    f.write("\n};")

    # Ending newline may be required for include files
    f.write("\n")

    f.close()
