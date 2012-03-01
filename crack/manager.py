
import sys
import re
import os.path
from pprint import pprint
from itertools import imap
from optparse import OptionParser

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

from distproc import WorkManager
import bittools

def count_inf(start=0, step=1):
    '''Generator yielding start+n*step for n=0,1,2,...'''
    while not self.done:
        yield start
        start += step

def get_num_chunk_bits():
    '''Extract NUM_CHUNK_BITS from input.h'''
    with open("input.h") as f:
        input_file = f.read()
    match = re.search("#define NUM_CHUNK_BITS (\d{1,2})", input_file)
    return int(match.group(1))

class DesWorkManager(WorkManager):

    def __init__(self, *args, **kwargs):

        self.results = []
        self.num_chunk_bits = get_num_chunk_bits()

        super(DesWorkManager, self).__init__(*args, **kwargs)

    def tasks(self):

        int_to_bin = lambda x: bin(x)[2:].rjust(56-self.num_chunk_bits, '0')
        for task in imap(int_to_bin, xrange(0, 2**self.num_chunk_bits)):
            if self.done:
                break
            yield task

    def process_result(self, result):
        #print "Tasks Finished:", self.tasks_finished
        if result[1]:
            self.results.append(result)
            print result
            self.done = True

    def finish(self):
        print "Results:"
        pprint(self.results)

if __name__ == "__main__":

    op = OptionParser(
        usage="%prog [options] [bind-address]:port",
        description="Start a service for DES crack workers to connect to."
    )
    op.add_option("-s", "--secret", type="string",
        dest="secret", default=None,
        help="Preshared secret that workers must use to authenticate.")

    options, args = op.parse_args()
    if len(args) == 1:

        match = re.match("^((.*):)?(.*)$", args[0])
        if match is None:
            op.error("URL must be in the format [address:]port")
        address = match.group(2) or ''
        port = None
        try:
            port = int(match.group(3))
        except ValueError: pass
        if not port:
            op.error("Invalid port number")

    elif len(args) > 1:
        op.error("Too many arguments")
    else:
        op.error("Not enough arguments")

    print "Running Manager on port %s" % port
    w = DesWorkManager(address, port, options.secret)
    w.run()
