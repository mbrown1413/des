
import os.path
import sys

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

import bittools
import desconst

if __name__ == "__main__":
    plaintext = bittools.hex_to_bits(sys.argv[1])

    # Initial Permutation
    processed = bittools.permute(plaintext, desconst.INITIAL_PERMUTATION)

    print bittools.bits_to_hex(processed)
