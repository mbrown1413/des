
DES Implementation Collection
=============================

Multiple implementations of DES (Data Encryption Standard) encryption and
decryption.  Includes the following:

* des.py
    Straightforward but slow.  Code is well documented and easy to follow.  A
    learning tool for people learning about DES.  Use -v to see DES done step
    by step.

* des.c
    Conversion of des.py into C.

* des_64.c
    Optimized based on techniques described below in the optimizations_
    section.  Useful learning tool to understand these optimizations

* crack/
    Distributed, optimized key search.  Takes in a known plaintext, ciphertext
    pair and tries every key until one of them works.  More information in
    ``crack/README.rst``


All but crack/ are learning tools for DES and optimizations.  In contrast,
crack/ is fully optimized and not meant for readability, although it is well
commented and as readable as it can be without sacrificing speed.

Usage
=====

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
=============

64 Bit Zip
----------
TODO

Permutation Elimination
-----------------------
TODO

Bitwise S-Boxes
---------------
TODO


TODO
====

* Make des.c and des_64.c take input on the command line.  Then update
  documentation in README.rst
* Consolidate tables and functions used in multiple C files.
* Make des_64.c do permutation elimination like crack/ does, i.e., do initial
  permutation first, so left and right block can be referenced as 0-31 and
  32-63.
* Make des.c and des_64.c do both encryption and decryption.
* Write crack/README.rst
* Remove some optimizations and clean up des.c; it should be easy to follow,
  not fast.
