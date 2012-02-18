
import sys
import os.path

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

import bittools

if __name__ == "__main__":

    key = bittools.hex_to_bits(sys.argv[1])
    #for i in [63, 55, 47, 39, 31, 23, 15, 7]:
    for i in [7, 15, 23, 31, 39, 47, 55, 63]:
        key.insert(i, 0)
    print bittools.bits_to_hex(key)
