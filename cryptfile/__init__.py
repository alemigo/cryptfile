#!/usr/bin/env python3
# -----------------------------
# cryptfile
# -----------------------------
#
"""General purpose Python encrypted file-like object that supports
   random access IO.
"""

__version__ = "1.0.4"
__author__ = "github.com/alemigo"

# Imports
from builtins import open as python_open
import os
import io
import struct
from Crypto.Cipher import AES  # PyCryptodome

# from cryptfile import *
__all__ = ["CryptFile", "open"]


class CryptFile(object):
    """Interface to perform random access IO to an encrypted file """

    file = None  # Python file object
    file_size = None  # Track size of file
    aes_key = None  # Encryption key (32 bytes for AES 256)
    cipher = None  # AES object
    file_closed = False  # Boolean has file been closed
    block_size = None  # Number of bytes per nonce (inclusive of 8 byte nonce)
    block_num = None  # Number of 16 byte AES blocks per cryptfile block
    fpos = None  # Position in file
    rpos = None  # Position in underlying file (ignores encryption)
    prior_rpos = None
    buffer = None  # Read buffer - data saved for next read
    cur_bindex = None
    last_io = None
    AES_BLOCK_SIZE = 16

    def __init__(self, file, mode, aes_key=None, block_num=10000):
        """Initialize cryptfile object"""
        if mode not in ("rb", "wb", "rb+", "wb+", "ab", "ab+"):
            raise ValueError("Supported modes: rb, wb, ab, rb+, wb+, ab+")
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
            omode = self.mode
            if omode in ["wb", "ab"]:
                omode += "+"  # force read access in underlying file
            self.file = python_open(file, omode)
        else:  # assume file-like object
            self.file = file

        # try to read block_size from file
        if self.mode in ("rb", "rb+", "ab", "ab+"):
            self.file.seek(0)
            inp = self.file.read(8)
            if inp:
                self.block_num = struct.unpack("<Q", inp)[0]
                self.block_size = (self.block_num * self.AES_BLOCK_SIZE) + 8

        if not self.block_size:
            self.block_num = block_num
            self.block_size = (self.block_num * self.AES_BLOCK_SIZE) + 8
            self.file.seek(0)
            self.file.write(
                struct.pack("<Q", self.block_num)
            )  # save num blocks, not bytes

        self.file_size = self.file.seek(0, 2)

        if "ab" in self.mode:
            self.fpos = self.file_size
        else:
            self.fpos = 8
            self.file.seek(8)

        self.rpos = self._calc_rpos(self.fpos)

    def write(self, data):
        """write method implementation"""
        if self.mode not in ("wb", "ab") and "+" not in self.mode:
            raise io.UnsupportedOperation("Cannot write in read mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        data_len = len(data)
        if data_len == 0:
            return 0
        data_pos = 0
        old_nonce = None
        new_nonce = False

        if self.last_io == "r" or self.rpos != self.prior_rpos:
            self.cur_bindex = None

        self.last_io = "w"
        if "ab" in self.mode and self.fpos < self.file_size:
            self.seek(0, 2)  # append mode only writes to the end

        while data_pos < data_len:
            wbuffer = io.BytesIO()
            wbuffer_len = 0

            (
                bindex,
                bstart,
                bpos,
                abindex,
                abstart,
                abpos,
                fabindex,
            ) = self._calc_pos_data(self.fpos)

            # get block nonce, or set new if doesnt exist (new block)
            if bindex != self.cur_bindex:
                new_nonce = True
                wstart = bstart + 8
                self.file.seek(bstart)
                old_nonce = self.file.read(8)
                self.nonce = os.urandom(8)
                self.cur_bindex = bindex

                if bpos > 8:  # prior data exists
                    self.file.seek(bstart + 8)
                    data2 = self.file.read(bpos - 8)

                    self.cipher = AES.new(
                        self.aes_key,
                        AES.MODE_CTR,
                        nonce=old_nonce,
                        initial_value=fabindex,
                    )
                    data2 = self.cipher.decrypt(data2)
                    wbuffer_len += wbuffer.write(data2)
            else:
                wstart = self.fpos

            write_len = min(
                data_len - data_pos, bstart + self.block_size - (abstart + abpos)
            )
            wbuffer_len += wbuffer.write(data[data_pos : data_pos + write_len])
            data_pos += write_len

            # end of write with room left in current block
            if (
                new_nonce
                and data_pos == data_len
                and bstart + self.block_size > (wstart + wbuffer_len)
            ):
                _, _, _, abindex2, abstart2, abpos2, fabindex2 = self._calc_pos_data(
                    wstart + wbuffer_len
                )

                # re_encrypt trailing data
                self.file.seek(abstart2)
                read_len = (self.block_num - abindex2) * self.AES_BLOCK_SIZE
                data2 = self.file.read(read_len)

                self.cipher = AES.new(
                    self.aes_key,
                    AES.MODE_CTR,
                    nonce=old_nonce,
                    initial_value=fabindex2 + abindex2,
                )
                data2 = self.cipher.decrypt(data2)
                wbuffer_len += wbuffer.write(data2[abpos2:])

            # write
            wbuffer.seek(0)
            if new_nonce:
                self.cipher = AES.new(
                    self.aes_key, AES.MODE_CTR, nonce=self.nonce, initial_value=fabindex
                )
                self.file.seek(bstart)
                self.fpos = bstart + self.file.write(
                    self.nonce + self.cipher.encrypt(wbuffer.read())
                )
            else:
                self.cipher = AES.new(
                    self.aes_key,
                    AES.MODE_CTR,
                    nonce=self.nonce,
                    initial_value=fabindex + abindex,
                )
                self.file.seek(wstart)
                self.fpos = wstart + self.file.write(
                    self.cipher.encrypt(b"0" * abpos + wbuffer.read())[abpos:]
                )

            self.rpos = self._calc_rpos(self.fpos)
            self.prior_rpos = self.rpos
            self.file_size = max(self.file_size, self.fpos)
            new_nonce = False

        return data_len

    def writelines(self, lines):
        """writelines implementation"""
        for line in lines:
            self.write(line)

    def read(self, size=-1, *, line=False):
        """read method implementation"""
        if self.mode != "rb" and "+" not in self.mode:
            raise io.UnsupportedOperation("Cannot read in write mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if self.last_io == "w":
            self.buffer = None
            self.cur_bindex = None

        self.last_io = "r"

        rbuffer = io.BytesIO()
        nl_found = False
        nl = -1
        if self.buffer:
            if line:
                nl = self.buffer.find(b"\n")
                if nl > -1:  # nl found
                    if size != -1:
                        rp = min(nl + 1, size)
                    rbuffer_len += rbuffer.write(self.buffer[:rp])
                    self.buffer = self.buffer[rp:]
                    nl_found = True

            if not line or nl == -1:  # not line mode or \n not found
                rbuffer_len = rbuffer.write(self.buffer)
                self.buffer = None
        else:
            rbuffer_len = 0

        while not nl_found and (size == -1 or rbuffer_len < size):
            # read data
            # get coordinates
            (
                bindex,
                bstart,
                bpos,
                abindex,
                abstart,
                abpos,
                fabindex,
            ) = self._calc_pos_data(self.fpos)

            # check if need to read new nonce
            if bindex != self.cur_bindex:
                self.file.seek(bstart)
                self.nonce = self.file.read(8)
                self.cur_bindex = bindex

            # read data
            self.file.seek(abstart)
            if size == -1:
                read_size = max(bstart + self.block_size - abstart, 0)
            else:
                read_size = max(
                    min(
                        abpos + (size - rbuffer_len), bstart + self.block_size - abstart
                    ),
                    0,
                )
            data = self.file.read(read_size)

            if len(data) <= abpos:  # EOF
                break

            # check if new cipher object needed
            self.cipher = AES.new(
                self.aes_key,
                AES.MODE_CTR,
                nonce=self.nonce,
                initial_value=fabindex + abindex,
            )

            data = self.cipher.decrypt(data)[abpos:]
            self.fpos += max(8 - bpos, 0) + len(data)

            nl = -1
            if line:
                nl = data.find(b"\n")
                if nl > -1:  # nl found
                    rbuffer_len += rbuffer.write(data[: nl + 1])
                    self.buffer = data[nl + 1 :]
                    break

            if not line or nl == -1:  # not line mode or \n not found
                rbuffer_len += rbuffer.write(data)

        # return data and adjust buffer
        self.rpos += rbuffer_len
        rbuffer.seek(0)
        return rbuffer.read()

    def readinto(b):
        """readinto implementation"""
        data = self.read()
        dlen = len(data)

        b[:dlen] = data
        return dlen

    def readline(self, size=-1):
        """readline implementation"""
        return self.read(size, line=True)

    def readlines(self, sizehint=0):
        """readlines implementation"""
        output = []
        while True:
            rr = self.readline()
            if rr == b"":
                break
            output.append(rr)

        return output

    def tell(self):
        """tell implementation"""
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self.rpos

    def seek(self, offset, whence=0):
        """seek implementation"""
        if self.closed:
            raise ValueError("I/O operation on closed file.")

        if whence not in (0, 1, 2):
            raise ValueError("Invalid whence value")

        # self.prior_rpos = self.rpos
        if whence == 0:  # absolute offset
            self.rpos = offset
        elif whence == 1:  # relative to current
            self.rpos += offset
        elif whence == 2:  # offset from end of file
            self.fpos = self.file.seek(0, 2)
            self.rpos = self._calc_rpos(self.fpos) + offset

        # note: does not support seeking past end of file
        self.rpos = min(max(self.rpos, 0), self._calc_rpos(self.file_size))
        self.fpos = self._calc_fpos(self.rpos)

        if self.rpos != self.prior_rpos:
            self.buffer = None

        return self.rpos

    def truncate(self, size=-1):
        """truncate implementation"""
        if "wb" not in self.mode and "+" not in self.mode:
            raise io.UnsupportedOperation("Cannot truncate in read mode")

        if self.closed:
            raise ValueError("I/O operation on closed file.")

        prior_rpos = self.rpos
        if size >= 0:
            rfsize = self.seek(0, 2)

            if size > rfsize:
                # write 0s to extend size of file
                write_size = size - rfsize
                self.write(b"0" * write_size)
                self.seek(prior_rpos)
                return size
        elif size == -1:
            size = self.rpos
        else:
            raise ValueError("Size parameter cannot be negative for truncate operation")

        self.fpos = self._calc_fpos(size)
        bpos = max(self.fpos - 8, 0) % self.block_size  # position within block

        if bpos <= 8:
            self.fpos -= bpos

        self.file.truncate(self.fpos)
        self.file_size = self.fpos
        self.seek(prior_rpos)
        return size

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
        if "rb" in self.mode or "+" in self.mode:
            return True
        else:
            return False

    def writable(self):
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        if "wb" in self.mode or "+" in self.mode:
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

    def _calc_rpos(self, fpos):
        bindex = max(fpos - 8, 0) // self.block_size
        return max(fpos - (8 * (bindex + 1)) - 8, 0)

    def _calc_fpos(self, rpos):
        bindex = rpos // (self.block_size - 8)
        return rpos + (8 * (bindex + 1)) + 8

    def _calc_pos_data(self, fpos):
        bindex = max(fpos - 8, 0) // self.block_size
        bstart = (bindex * self.block_size) + 8
        bpos = max(fpos - 8, 0) % self.block_size  # position within block

        abindex = max(bpos - 8, 0) // self.AES_BLOCK_SIZE  # index within block
        abstart = bstart + 8 + (abindex * self.AES_BLOCK_SIZE)
        abpos = max(bpos - 8, 0) % self.AES_BLOCK_SIZE  # position within aes block

        fabindex = bindex * self.block_num  # index of first aes block in whole file
        return bindex, bstart, bpos, abindex, abstart, abpos, fabindex

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


def open(file, mode, aes_key=None, block_num=1000):
    """alternative constructor"""
    return CryptFile(file, mode, aes_key=aes_key, block_num=block_num)
