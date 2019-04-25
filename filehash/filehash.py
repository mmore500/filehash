import abc
import glob
import hashlib
import os
import os.path
import zlib


class ZlibHasherBase():
    """
    Wrapper around zlib checksum functions to calculate a checksum with a similar
    interface as the algorithms in hashlib.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        pass

    @abc.abstractmethod
    def update(self, arg):
        """
        Update the hash object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).

        :param arg: String to update the digest with.
        """
        pass

    def digest(self):
        """
        Return the digest of the strings passed to the update() method so far.
        This is a string of digest_size bytes which may contain non-ASCII
        characters, including null bytes.
        """
        return self._digest

    def hexdigest(self):
        """
        Like digest() except the digest is returned as a string of double length,
        containing only hexadecimal digists.  This may be used to exchange the
        value safely in email or other non-binary environments.
        """
        return hex(self._digest).upper()[2:]

    @abc.abstractmethod
    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        pass


class Adler32(ZlibHasherBase):
    """
    Wrapper around zlib.adler32 to calculate the adler32 checksum with a similar
    interface as the algorithms in hashlib.
    """
    name = 'adler32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        self._digest = 1
        if arg is not None:
            self.update(arg)

    def update(self, arg):
        """
        Update the adler32 object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).
        :param arg: String to update the digest with.
        """
        self._digest = zlib.adler32(arg, self._digest) & 0xFFFFFFFF

    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        copy = Adler32()
        copy._digest = self._digest
        return copy


class CRC32(ZlibHasherBase):
    """
    Wrapper around zlib.crc32 to calculate the crc32 checksum with a similar
    interface as the algorithms in hashlib.
    """
    name = 'crc32'
    digest_size = 4
    block_size = 1

    def __init__(self, arg=None):
        """
        Initialize the class.

        :param arg: String to calculate the digest for.
        """
        self._digest = 0
        if arg is not None:
            self.update(arg)

    def update(self, arg):
        """
        Update the crc32 object with the string arg.  Repeated calls are
        equivalent to a single call with the concatenation of all the arguments:
        m.update(a); m.update(b) is equivalent to m.update(a+b).
        :param arg: String to update the digest with.
        """
        self._digest = zlib.crc32(arg, self._digest) & 0xFFFFFFFF

    def copy(self):
        """
        Return a copy ("clone") of the hash object.  This can be used to
        efficiently compute the digests of strings that share a common initial
        substring.
        """
        copy = CRC32()
        copy._digest = self._digest
        return copy


class FileHash:
    """
    Class wrapping the hashlib module to facilitate calculating file hashes.
    """

    def __init__(self, hash_algorithm='sha256', chunk_size=4096):
        """
        Initialize the FileHash class.

        :param hash_algorithm: String representing the hash algorithm to use.
                               See SUPPORTED_ALGORITHMS to see a list
                               of valid values.  Defaults to 'sha256'.
        :param chunk_size: Integer value specifying the chunk size (in bytes)
                           when reading files.  Files will be read in chunks
                           instead of reading the entire file into memory all at
                           once.  Defaults to 4096 bytes.
        """
        if hash_algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError("Error, unsupported hash/checksum algorithm: {0}".format(hash_algorithm))
        self.chunk_size = chunk_size
        self.hash_algorithm = hash_algorithm

    def hash_file(self, filename):
        """
        Method for calculating the hash of a file.

        :param filename: Name of the file to calculate the hash for.
        :returns: Digest of the file, in hex.
        """
        with open(filename, mode="rb", buffering=0) as fp:
            hash_func = _ALGORITHM_MAP[self.hash_algorithm]()
            buffer = fp.read(self.chunk_size)
            while len(buffer) > 0:
                hash_func.update(buffer)
                buffer = fp.read(self.chunk_size)
        return hash_func.hexdigest()

    def cathash_files(self, filenames):
        """
        Method for calculating a single hash from multiple files.
        Files are sorted by their individual hash values and then traversed in that order to generate a combined hash value.

        :param filenames: List of names of files to calculate the hash for.
        :returns: Digest of the files, in hex.
        """
        hash_func = _ALGORITHM_MAP[self.hash_algorithm]()
        for filename in sorted(filenames, key=lambda x: self.hash_file(x)):
            with open(filename, mode="rb", buffering=0) as fp:
                buffer = fp.read(self.chunk_size)
                while len(buffer) > 0:
                    hash_func.update(buffer)
                    buffer = fp.read(self.chunk_size)
        return hash_func.hexdigest()

_ALGORITHM_MAP = {
    'adler32': Adler32,
    'crc32': CRC32,
    'md5' : hashlib.md5,
    'sha1' : hashlib.sha1,
    'sha256' : hashlib.sha256,
    'sha512' : hashlib.sha512,
}

SUPPORTED_ALGORITHMS = set(_ALGORITHM_MAP.keys())
