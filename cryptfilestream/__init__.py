#!/usr/bin/env python3
# -----------------------------
# cryptfilestream
# -----------------------------
#
"""Python encrypted file-like object that supports stream IO.
"""

__version__ = "1.0.5"
__author__ = "github.com/alemigo"

# Imports
from builtins import open as python_open
import os
import io
from Crypto.Cipher import AES  # PyCryptodome

# from cryptfilestream import *
__all__ = ["CryptFileStream", "open"]


class CryptFileStream(object):
    """Interface to perform stream IO to an encrypted file """

    file = None  # Python file object
    aes_key = None  # Encryption key (32 bytes for AES 256)
    cipher = None  # AES object
    file_closed = False  # Boolean has file been closed
    buffer = b""  # Read buffer - data saved for next read
    BUFFER_SIZE = 16 * 1024

    def __init__(self, file, mode, aes_key=None):
        """Initialize cryptfilestream object"""
        if mode not in ("rb", "wb"):
            raise ValueError("Supported modes: rb, wb")
        else:
            self.mode = mode

        if aes_key:  # key provided
            if len(aes_key) != 32:
                raise ValueError("32 byte encryption key required")
            else:
                self.aes_key = aes_key
        else:  # create random key
            self.aes_key = os.urandom(32)

        if isinstance(file, str):
            self.file = python_open(file, self.mode)
        else:  # assume file-like object
            self.file = file

        if mode == "rb":
            nonce = self.file.read(8)
        elif mode == "wb":
            nonce = os.urandom(8)
            self.file.write(nonce)

        self.cipher = AES.new(self.aes_key, AES.MODE_CTR, nonce=nonce)

    def write(self, data):
        """write method implementation"""
        if self.mode != "wb":
            raise io.UnsupportedOperation("Cannot write in read mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        return self.file.write(self.cipher.encrypt(data))

    def writelines(self, lines):
        """writelines implementation"""
        for line in lines:
            self.write(line)

    def read(self, size=-1):
        """read method implementation"""
        if self.mode != "rb":
            raise io.UnsupportedOperation("Cannot read in write mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if size == -1:
            output = self.buffer
            self.buffer = b""
            return output + self.cipher.decrypt(self.file.read(-1))
        else:
            output = self.buffer[:size]
            self.buffer = self.buffer[size:]
            output_len = len(output)

            if output_len < size:
                return output + self.cipher.decrypt(self.file.read(size - output_len))
            else:
                return output

    def readinto(b):
        """readinto implementation"""
        data = self.read()
        dlen = len(data)

        b[:dlen] = data
        return dlen

    def readline(self, size=-1):
        """readline implementation"""
        rbuffer = io.BytesIO()
        rbuffer_len = 0
        nl_found = False
        nl = -1
        if len(self.buffer) > 0:
            nl = self.buffer.find(b"\n")
            if nl > -1:  # nl found
                if size != -1:
                    nl = min(nl, size - 1)
                rbuffer_len += rbuffer.write(self.buffer[:nl+1])
                self.buffer = self.buffer[nl+1:]
                nl_found = True
            else:
                rbuffer_len = rbuffer.write(self.buffer)
                self.buffer = b""

        while not nl_found and (size == -1 or rbuffer_len < size):
            # read data
            if size == -1:
                read_size = self.BUFFER_SIZE
            else:
                read_size = min(self.BUFFER_SIZE, size - rbuffer_len)

            data = self.cipher.decrypt(self.file.read(read_size))
            if data == b"":
                break

            nl = data.find(b"\n")
            if nl > -1:  # nl found
                rbuffer_len += rbuffer.write(data[: nl + 1])
                self.buffer = data[nl + 1 :]
                break
            else:
                rbuffer_len += rbuffer.write(data)

        # return data
        rbuffer.seek(0)
        return rbuffer.read()

    def readlines(self, sizehint=0):
        """readlines implementation"""
        output = []
        while True:
            rr = self.readline()
            if rr == b"":
                break
            output.append(rr)

        return output

    def truncate(self, size=-1):
        """truncate implementation"""
        if "wb" not in self.mode:
            raise io.UnsupportedOperation("Cannot truncate in read mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        return self.file.truncate(size)

    def close(self):
        """close file implementation"""
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if self.file:
            self.file.close()
            self.file = None

        self.file_closed = True
        self.buffer = None
        self.aes_key = None
        self.nonce = None
        self.cipher = None

    def readable(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if "rb" in self.mode:
            return True
        else:
            return False

    def writable(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if "wb" in self.mode:
            return True
        else:
            return False

    def seekable(self):
        return self.file.seekable()

    def flush(self):
        return self.file.flush()

    @property
    def closed(self):
        return self.file_closed

    @property
    def aeskey(self):
        return self.aes_key

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __iter__(self):
        return self

    def __next__(self):
        r = self.readline()
        if r == b"":
            raise StopIteration
        else:
            return r


def open(file, mode, aes_key=None):
    """alternative constructor"""
    return CryptFileStream(file, mode, aes_key=aes_key)
