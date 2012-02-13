

import os.path
import sys
from pprint import pprint
from itertools import imap

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

from distproc import WorkManager

NUM_CHUNK_BITS = 28

def count_inf(start=0, step=1):
    while not self.done:
        yield start
        start += step

class DesWorkManager(WorkManager):

    def __init__(self, *args, **kwargs):

        self.results = []

        super(DesWorkManager, self).__init__(*args, **kwargs)

    def tasks(self):

        for task in imap(lambda x: ("%0"+str(56-NUM_CHUNK_BITS)+"d") % int(bin(x)[2:]), xrange(0, 2**NUM_CHUNK_BITS)):
            if self.done:
                break
            yield task

    def process_result(self, result):
        print "Tasks Finished:", self.tasks_finished
        if result[1]:
            self.results.append(result)
            print result
            self.done = True

    def finish(self):
        print "Results:"
        pprint(self.results)

if __name__ == "__main__":

    w = DesWorkManager('', 50000, "secret")
    w.run()
