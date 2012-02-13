
import sys
import os.path

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

import bittools

if __name__ == "__main__":

    bits = bittools.hex_to_bits(sys.argv[1])

    zipped = zip(*(bits for i in xrange(64)))

    print "        // Zipped 0x%s 64 times" % sys.argv[1]

    width = 4
    for i, item in enumerate(zipped):
        if i%width == 0:
            print "       ",
        if i == 63:
            print "0x%sLL" % bittools.bits_to_hex(item),
        else:
            print "0x%sLL," % bittools.bits_to_hex(item),
        if i%width == width-1:
            print
