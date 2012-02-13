
import os.path
import sys
from subprocess import Popen, PIPE, CalledProcessError

# Add lib/ to sys.path
lib_directory = os.path.realpath(os.path.join(__file__, "../../lib/"))
sys.path.append(lib_directory)

from distproc import Worker

def check_output(*popenargs, **kwargs):
    """Copied from python2.7.2 subprocess."""

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = Popen(stdout=PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise CalledProcessError(retcode, cmd)
    return output

class DesWorker(Worker):

    def do_task(self, data):
        print "Doing Task", data
        return check_output(["./crack/check_keys", data])

if __name__ == "__main__":

    w = DesWorker('127.0.0.1', 50000, "secret")
    w.run()
