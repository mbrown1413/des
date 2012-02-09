
from subprocess import Popen, PIPE, CalledProcessError

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

class HashWorker(Worker):

    def do_task(self, data):
        print "Doing Task", data
        return check_output(["./crack/check_keys", data])

if __name__ == "__main__":

    w = HashWorker('127.0.0.1', 50000, "secret")
    w.run()
