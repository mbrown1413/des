
import sys
import os.path

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

import bittools

if __name__ == "__main__":

    key = bittools.hex_to_bits(sys.argv[1])
    for i in [63, 55, 47, 39, 31, 23, 15, 7]:
        key.pop(i)
    print bittools.bits_to_hex(key)
