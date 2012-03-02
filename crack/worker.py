
import re
import sys
import os.path
from optparse import OptionParser
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
        print "Checking Prefix:", data
        return check_output(["./check_keys", data])

if __name__ == "__main__":

    op = OptionParser(
        usage="%prog [options] address:port",
        description="Start a worker for a DES crack manager.  Address defaults to localhost."
    )
    op.add_option("-s", "--secret", type="string",
        dest="secret", default=None,
        help="Preshared secret that the manager was started with.")

    options, args = op.parse_args()
    if len(args) == 1:

        match = re.match("^((.*):)?(.*)$", args[0])
        if match is None:
            op.error("URL must be in the format [address:]port")
        address = match.group(2) or '127.0.0.1'
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

    try:
        w = DesWorker(address, port, options.secret)
    except AssertionError as e:
        import traceback
        traceback.print_exc()
        print "Error probably due to key mismatch"
        sys.exit()

    print "Connected to manager at %s:%s" % (address, port)
    w.run()
