
=============================
DES Implementation Collection
=============================

Multiple implementations of DES (Data Encryption Standard) encryption and
decryption.  Includes the following:

* des.py
    Straightforward but slow.  Well documented and easy to follow; a good
    learning tool for people new to DES.

* des.c
    Conversion of des.py into C.

* des_64.c
    Optimized based on techniques described below in the optimizations
    section.  Useful learning tool to understand these optimizations

* crack/
    Distributed, optimized key search (known plaintext attack).  Takes a known
    plaintext, ciphertext pair and tries every key until one of them works.
    More information in `/crack/README.rst
    <https://github.com/mbrown1413/des/blob/master/crack/README.rst>`_

All implementations except for crack/ are learning tools for DES and
optimizations.  In contrast, crack/ is fully optimized and not meant for
readability, although it is well commented and as readable as it can be without
sacrificing speed.


des.py
------

To encrypt, run des.py using Python and pass in your plaintext and key in hex::

    $ python des.py beefbeefbeefbeef 0123456789abcdef
    45c4afc7a174e828

Here, ``beefbeefbeefbeef`` is the plaintext and ``0123456789abcdef`` is the
key.  They both must be 16 hex digits.

To decrypt, use the -d option and give ciphertext instead of plaintext::

    $ python des.py -d 45c4afc7a174e828 0123456789abcdef
    beefbeefbeefbeef

ASCII Input/Output
``````````````````
If you want to give the plaintext with 8 ASCII characters, use the -a option::

    $ python des.py -a ascichrs 0123456789abcdef
    065c67acb4b351d6

When decrypting, -a will instead convert the resulting plaintext into ASCII::

    $ python des.py -a -d 065c67acb4b351d6 0123456789abcdef
    ascichrs

Verbose Output
``````````````

You can also use the -v option to have it show detailed step by step
calculations::

    $ python des.py -v beefbeefbeefbeef 0123456789abcdef

Use this for your homework!


des.c and des_64.c
------------------

You will need GNU Make and gcc.  To compile, run make::

    $ make

This will create executables ``des`` and ``des_64``.

For now, there is no way to provide input on the command line.  Sorry, it's in
the TODO list.  You will have to put the input in the code yourself.  Currently
``des`` and ``des_64`` are set up to run many encryptions as a speed test.


Optimizations
-------------

These optimizations were proposed by Eli Biham in the paper "A Fast New DES
Implementation in Software".

64-Bit Parallel
```````````````

This is a way to do 64 encryptions simultaneously utilizing 64-bit integers.

Consider the normal way to do 64 encryptions at once.  We would store each key,
plaintext and ciphertext in an array.  Then, every time we do an operation, we
do it to all 64.  Now consider how one of these values, the key for example, is
stored.  They would be stored in an array like this:

.. csv-table:: Normal Format

              , Bit 1, Bit 2, Bit 3, Bit 4, Bit 5, ...
   int64 Key 1,     a,     b,     c,     d,     e, ...
   int64 Key 2,     f,     g,     h,     i,     j, ...
   int64 Key 3,     k,     l,     m,     n,     o, ...
   int64 Key 4,     p,     q,     r,     s,     t, ...
   int64 Key 5,     u,     v,     w,     x,     y, ...
           ...,   ...,   ...,   ...,   ...,   ..., ...

Each row contains a key.  We can store each key as a 64-bit integer, so we
would have an array of 64 integers.  Now suppose we transpose the table above:

.. csv-table:: Zipped Format

              , Key 1, Key 2, Key 3, Key 4, Key 5, ...
   int64 Bit 1,     a,     f,     k,     p,     u, ...
   int64 Bit 2,     b,     g,     l,     q,     v, ...
   int64 Bit 3,     c,     h,     m,     r,     w, ...
   int64 Bit 4,     d,     i,     n,     s,     x, ...
   int64 Bit 5,     e,     j,     o,     t,     y, ...
           ...,   ...,   ...,   ...,   ...,   ..., ...

We store each row in a 64-bit integer, again giving us an array of 64 integers.
We call this zipped format.  Now instead of looping through each of the 64
parallel encryptions to do an operation, we can just do the operation on one
64-bit integer.  For example, Doing an xor with two elements of arrays in this
format, a single xor instruction will simultaneously do an xor for all 64
encryptions.

When you see functions like zip_64_bit in the code, these convert from normal
to zipped format.  Since this is like transposing a matrix, zip_64_bit is its
own inverse.

Permutation Elimination
```````````````````````

Permutations are expensive and DES requires a lot of them.  But we don't
actually have to permute things in memory in order to compute the result.
Instead, we can index the bit that would be used if the permutation were
actually performed.  Biham explains this as "changing the naming of the
registers."  This includes the expansion step as well.

This is best explained by example.  Consider this pseudocode::

    bit a, b, x, y
    swap(a, b)
    x = xor(a, x)
    y = xor(b, y)

It's pretty obvious the swap is unnecessary::

    bit a, b, x, y
    x = xor(b, x)
    y = xor(a, y)

Eliminating permutations is the same idea on a larger scale.

Bitwise S-Boxes
```````````````

Traditionally, s-boxes are implemented with lookup tables.  But s-boxes can
actually be implemented using nothing but logic gate operations, which is much
faster, especially when using the 64-bit parallel optimization.

Finding the optimum logic design of s-boxes is very non-trivial.  A Eli Biham
talks about this in his paper "A Fast New DES Implementation in Software", but
Matthew Kwan's page entitled `bitslice <http://www.darkside.com.au/bitslice/>`_
has much more up to date information, as well as some history.

The fastest implementation I know about is implemented in `John the Ripper
<http://www.openwall.com/john/>`_.  They actually have
multiple implementations, and the fastest one is automatically chosen.

This project's bitwise DES s-box implementation can be found in
``include/sbox.h``, which defines functions s0 through s7.  I didn't come up
with any designs myself.
