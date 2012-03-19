
=========
DES Crack
=========

A distributed exhaustive key search.  Given a plaintext-ciphertext pair, every
possible key is tried until decrypting the ciphertext results in the plaintext.


Architecture
------------

::

                  manager.py
                     |
                     | Coordinates
                     |
                     V
        +------------+------------+------------+---
        |            |            |            |
        V            V            V            |
     worker.py    worker.py    worker.py     .....
        |            |            |            |
        |            |            |            |
        +------------+------------+------------+---
                     |
                     | Executes
                     |
                     V
                 check_keys
                     |
                     | Includes
                     |
                     V
                  input.h
                     ^
                     |
                     | Generates
                     |
                 set_input.py

check_keys
``````````

``check_keys`` is the core of the key search.  ``check_keys`` takes the first
``56-NUM_CHUNK_BITS`` bits of a key as an argument and checks to see if any
keys with that prefix works with the given plaintext-cyphertext pair.

``NUM_CHUNK_BITS``, defined in ``input.h``, is the number of bits that a single
execution of check_keys will exhaustively search.  Thus, check_keys takes the
first ``56-NUM_CHUNK_BITS`` bits and checks ``2**NUM_CHUNK_BITS`` keys for each
execution.  ``NUM_CHUNK_BITS`` must be at least 6, since decryptions are
done 64 at a time (and 64 = 2**6).

In order to check all possible keys, we're going to execute ``check_keys`` many
times, so its startup time can affect performance a lot.  For this reason, the
plaintext and ciphertext are pre-permuted, pre-zipped, and stored in
``input.h`` before compilation.  This is done by ``set_input.py``, which takes
the plaintext, ciphertext and NUM_CHUNK_BITS, and stores them in ``input.h``
after doing these precomputations.  ``input.h`` is then included from
``check_keys.c`` on compilation.

Distributed Processing
``````````````````````

In order to run ``check_keys`` many times on possibly many computers, a
manager-worker model is used.  One instance of the manager runs to coordinate
the workers.  Workers connect to the manager, ask for a task to compute (the
task will be the key prefix to pass to ``check_keys``), then return the result
and repeat.

Mutual authentication is done between the worker and manager using HMAC.  Both
worker and manager must specify the same ``-s`` or ``--secret`` argument (or
both omit the option) or they will not authenticate.  It is important to note
that authentication is done `only` on connection.  Any messages after
connection are not encrypted or authenticated.  If somebody manages to get a
worker or manager to de-serialize some data, he can execute arbitrary code on
your machine!  This is due to the nature of the Python `pickle
<http://docs.python.org/library/pickle.html>`_ module.

If a worker exits while in the middle of a task, the manager will notice and
assign the task to another worker.  In practice this isn't perfect.  For
example a manager may not notice a worker's absence if the connection isn't
closed cleanly.  You can at least kill the program with a keyboard interrupt
without fear of dropping tasks.


Running check_keys
------------------

As an example, let's make our plaintext be all 0's, and ciphertext be all
1's::

    $ python ../des.py 0000000000000000 ffffffffffffffff
    caaaaf4deaf1dbae

So "caaaaf4deaf1dbae" is our ciphertext".  Now we use ``set_input.py`` to
generate ``input.h`` for this plaintext-ciphertext pair.  We'll choose
``NUM_CHUNK_BITS`` to be 26, so each chunk won't take very long to run::

    $ python set_input.py 0000000000000000 caaaaf4deaf1dbae 26

Now that ``input.h`` exists, we can compile ``check_keys``::

    $ make
    cc -std=c99 -Werror -pedantic -O3 -lm -Wno-missing-prototypes -I../include/ check_keys.c -o check_keys

Now if we run ``check_keys`` with the first ``56-NUM_CHUNK_BITS`` of our key it
will recover the full key::

    $ ./check_keys 111111111111111111111111111111
    0xffffffffffffff

The first and only argument is the key prefix in binary.  It's not given in hex
since that would take extra time to parse.

Notice that the output is only 56 bits.  Remember that only 56 bits are used
from a 64-bit key, so that's all ``check_keys`` gives us.  To expand the key to
64 bits use ``expand_key.py``::

    $ python expand_key.py ffffffffffffff
    fefefefefefefefe

The unused bits are filled with zero, which is why the resulting key is
actually different than the original.  They both of course work the same::

    $ python ../des.py 0000000000000000 ffffffffffffffff
    caaaaf4deaf1dbae

    $ python ../des.py 0000000000000000 fefefefefefefefe
    caaaaf4deaf1dbae

Running Distributed
-------------------

First, make sure check_keys is set up correctly and compiled, as described
above.  This needs to be done on each machine if you plan on using multiple
computers.  Make sure the same ``set_input.py`` command is used for each
machine and you compile ``check_keys`` afterwards::

    $ python set_input.py 0000000000000000 caaaaf4deaf1dbae 26
    $ make
    cc -std=c99 -Werror -pedantic -O3 -lm -Wno-missing-prototypes -I../include/ check_keys.c -o check_keys

You should probably make ``NUM_CHUNK_BITS`` larger than 26.  There will be
``2**(56-NUM_CHUNK_BITS)`` number of tasks do divide between workers, and if there are
too many tasks, the overhead of distributed processing will get too large.  You
should grow ``NUM_CHUNK_BITS`` until each run of ``check_keys`` takes at least
on the order of seconds, preferably minutes.  Somewhere around 30 to 32 is
usually a good number in my experience.

Now start the manager on a computer that can be accessed by all of the others::

    $ python manager.py -s mysecret 0.0.0.0:8000

The ``-s`` option gives the secret that the workers need to use to connect.
The ``0.0.0.0`` address tells the manager to listen to outside connections on
any address.  The default is to only accept local connections.  The port chosen
here is 8000, but you can use any valid unused port you want.

Now to start a worker::

    $ python worker.py -s mysecret 127.0.0.1:8000
    == Worker 0 == Connected to manager at 127.0.0.1:8000
    == Worker 0 == Checking Prefix: 000000000000000000000000000000
    == Worker 0 == Checking Prefix: 000000000000000000000000000001
    == Worker 0 == Checking Prefix: 000000000000000000000000000010
    ...

This worker was started on the local machine, hence the 127.0.0.1 loopback
address.  You can start workers on different machines and different networks if
you want.  When a worker connects or disconnects, the manager will show it.
The manager and worker will immediately show when a valid key has been found.
The manager also keeps a list of results and displays them at the end.

A useful feature of worker.py is the ``-c`` or ``--count`` option to start
multiple workers::

    $ python worker.py -s mysecret 127.0.0.1:8000 -c 4
    == Worker 0 == Connected to manager at 127.0.0.1:8000
    == Worker 1 == Connected to manager at 127.0.0.1:8000
    == Worker 2 == Connected to manager at 127.0.0.1:8000
    == Worker 3 == Connected to manager at 127.0.0.1:8000
    == Worker 0 == Checking Prefix: 000000000000000000000000000000
    == Worker 1 == Checking Prefix: 000000000000000000000000000010
    == Worker 2 == Checking Prefix: 000000000000000000000000000100
    == Worker 3 == Checking Prefix: 000000000000000000000000000110
    ...
