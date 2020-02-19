General purpose Python encrypted file-like object that facilitates random access IO.  Uses AES encryption in CTR mode.  Can be used with modules such as tarfile, zipfile, lzma, pickle, json and others that accept a file-like object as an alternative to a path.  Supports binary IO modes only.

### Examples
```
import cryptfile

with cryptfile.open('data.bin', 'wb+', aes_key=b'256 bit key', block_num=5000) as f:
    f.write(b'Hello, World!')
    f.seek(0)
    print(f.read())
     
Result:
b'Hello, World!'
```
### Documentation

cryptfile.**open**(*file, mode, aes_key=None, block_num=10000*)

Returns a CryptFile object for a specified file.  
 - *file* can either be a string containing a valid path, or a file-like object.
 - Supported *mode* values are: `wb, wb+, rb, rb+, ab, ab+`. 
 - 256 bit binary *aes_key* is used for en/decryption, or if none is provided for a new file, a random key is generated and is retrievable with the `.aeskey` property.
 - *block_num* sets the number of 16 byte AES blocks per cryptfile block for new files.  Each cryptfile block stores its own 8 byte nonce value, and is re-written in whole if any part of the block is altered.  Larger *block_num* values optimize for more sequential IO, whereas smaller values optimize for smaller random IO that jumps around the file.  This argument is not needed for opening existing files.  

### Dependencies

PyCryptodome for AES encryption

### Installation

pip install cryptfile
