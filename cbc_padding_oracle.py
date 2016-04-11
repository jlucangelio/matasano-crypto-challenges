import utils
import random
import sys

from collections import deque

STRINGS = """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".splitlines()

KEY = utils.ByteArray.random_key()

def encrypt():
    s = random.choice(STRINGS)
    p = utils.ByteArray.fromBase64(s)
    # q = utils.ByteArray.fromBase64(s)
    # q.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)
    # print q.asHexString()
    iv = utils.ByteArray.random_block()
    c = utils.aes_cbc_encrypt(p, KEY, iv)
    return c, iv


def decrypt(ciphertext, iv):
    plaintext = utils.aes_cbc_decrypt(ciphertext, KEY, iv)
    # print "plaintext", plaintext.blocksAsHexStrings(utils.AES_BLOCKSIZE_BYTES)
    try:
        utils.pkcs7validate(plaintext)
    except:
        return False

    # print "valid plaintext", plaintext.blocksAsHexStrings(utils.AES_BLOCKSIZE_BYTES)
    return True


c, iv = encrypt()

if len(c) < 3:
    print "short ciphertext"
    sys.exit(1)

previous_cblock = c.block(utils.AES_BLOCKSIZE_BYTES, -2)
corrupted = utils.ByteArray.fromHexString("00" * utils.AES_BLOCKSIZE_BYTES)
corrupted.extend(c.block(utils.AES_BLOCKSIZE_BYTES, -1))
# print "len(corrupted)", len(corrupted)

decrypted_bytes = [None for _ in range(16)]
# for count in range(1, utils.AES_BLOCKSIZE_BYTES + 1):
for count in range(1, 2):
    print "count", count
    byte_idx = utils.AES_BLOCKSIZE_BYTES - count
    print "byte_idx", byte_idx
    padding_value = count

    # Set previous bytes.
    # for prev_idx in range(utils.AES_BLOCKSIZE_BYTES - count + 1, utils.AES_BLOCKSIZE_BYTES):
    #     print "prev_idx", prev_idx
    #     ri = corrupted.get_byte(prev_idx)
    #     corrupted.set_byte(prev_idx, ri ^ decrypted_bytes[prev_idx] ^ padding_value)

    # Try current byte.
    for i in range(256):
        rb = corrupted.get_byte(byte_idx)
        corrupted.set_byte(byte_idx, i)
        if decrypt(corrupted, iv):
            decrypted_bytes[byte_idx] = hex(previous_cblock.get_byte(byte_idx) ^ i ^ 0x1)
            corrupted.set_byte(byte_idx, rb)
            break

print decrypted_bytes
