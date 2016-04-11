import utils
import random
import sys

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
    p.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)
    print hex(p.block(utils.AES_BLOCKSIZE_BYTES, -2).get_byte(-1))
    iv = utils.ByteArray.random_block()
    c = utils.aes_cbc_encrypt(p, KEY, iv)
    return c, iv

def decrypt(ciphertext, iv):
    plaintext = utils.aes_cbc_decrypt(ciphertext, KEY, iv)
    try:
        utils.pkcs7validate(plaintext)
    except:
        return False

    return True


c, iv = encrypt()

if len(c) < 3:
    print "short ciphertext"
    sys.exit(1)

corrupted = c.block(utils.AES_BLOCKSIZE_BYTES, -3)
# corrupted = utils.ByteArray.random_block()
corrupted.extend(c.block(utils.AES_BLOCKSIZE_BYTES, -2))
print "len(corrupted)", len(corrupted)

for i in range(256):
    r = corrupted.get_byte(15)
    corrupted.set_byte(15, r ^ i)
    if decrypt(corrupted, iv):
        print "res", hex(r ^ 0x1)
        break
