``fileshash``
============

.. image:: https://img.shields.io/pypi/v/fileshash.svg
        :target: https://pypi.python.org/pypi/fileshash

.. image:: https://img.shields.io/travis/mmore500/fileshash.svg
        :target: https://travis-ci.org/mmore500/fileshash

Python module to facilitate calculating the hash of multiple files.
Tested against Python 2.7, Python 3.6, PyPy 2.7 and PyPy 3.5.
Currently supports `Adler-32 <https://en.wikipedia.org/wiki/Adler-32>`_, `CRC32 <https://en.wikipedia.org/wiki/Cyclic_redundancy_check>`_, `MD5 <https://en.wikipedia.org/wiki/MD5>`_, `SHA-1 <https://en.wikipedia.org/wiki/SHA-1>`_, `SHA-256 and SHA-512 <https://en.wikipedia.org/wiki/SHA-2>`_.

Forked from Leonides T. Saguisag Jr.'s `FileHash <https://github.com/leonidessaguisagjr/filehash>`_.

``FilesHash`` class
------------------

The ``FilesHash`` class wraps around the ``hashlib`` (provides hashing for MD5, SHA-1, SHA-256 and SHA-512) and ``zlib`` (provides checksums for Adler-32 and CRC32) modules and contains the following methods:

- ``hash_file(filename)`` - Calculate the file hash for a single file.  Returns a string with the hex digest.
- ``cathash_files(filenames)`` - TODO
- ``hophash_files(filenames)`` - TODO

The ``FileHash`` constructor has two optional arguments:

- ``hash_algorithm='sha256'`` - Specifies the hashing algorithm to use.
See ``filehash.SUPPORTED_ALGORITHMS`` for the list of supported hash / checksum algorithms.
Defaults to SHA256.
- ``chunk_size=4096`` - Integer specifying the chunk size to use (in bytes) when reading the file.
This comes in useful when processing very large files to avoid having to read the entire file into memory all at once.  Default chunk size is 4096 bytes.

Example usage
-------------

The library can be used as follows::

   >>> import os
   >>> from fileshash import FilesHash
   >>> TODO


``fileshash`` command line tool
---------------------------------

A command-line tool called ``fileshash`` is also included with the ``fileshash`` package.
Here is an example of how the tool can be used::

   $ TODO

Run the tool without any parameters or with the ``-h`` / ``--help`` switch to get a usage screen.

License
-------

This is released under an MIT license.
See the ``LICENSE`` file in this repository for more information.
