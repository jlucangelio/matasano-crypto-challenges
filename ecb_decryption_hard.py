import utils

# import Crypto.Random.random as random
import random

import ecb_cbc_detection


UNKNOWN_STRING = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = utils.ByteArray.random(utils.AES_BLOCKSIZE_BYTES)
PREFIX = utils.ByteArray.random(random.randrange(1, utils.AES_BLOCKSIZE_BYTES))


def oracle(input_data):
    plaintext = utils.ByteArray()
    plaintext.extend(PREFIX)
    plaintext.extend(utils.ByteArray.fromString(input_data))
    plaintext.extend(utils.ByteArray.fromBase64(UNKNOWN_STRING))
    plaintext.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)

    ret = utils.aes_ecb_encrypt(plaintext, KEY)
    return ret


def find_prefix_length(bs):
    zeros = "0" * bs * 2

    for i in range(bs):
        prefix = "0" * i + zeros
        print prefix
        ctext = oracle(prefix)
        blocks = ctext.blocksAsHexStrings(bs)

        last_block = blocks[0]
        for bindex, block in enumerate(blocks):
            if bindex == 0:
                continue
            if block == last_block:
                return bs - i

            last_block = block

    print "Can't find prefix length"


if __name__ == "__main__":
    print oracle("subidubisubidubi").asHexString()

    bs = None
    padding = None

    l = min([len(oracle("")) for _ in range(8)])
    print l
    for i in range(32):
        ctext = oracle("A" * (i+1))
        if len(ctext) != l:
            bs = abs(len(ctext) - l)
            padding = i
            break

    print "block size", bs
    print "padding", padding

    if ecb_cbc_detection.detect_ecb_cbc(oracle) != "ECB":
        print "Not ECB"

    unknown_string = ""
    blocks = {}

    prefix_length = find_prefix_length(bs)
    print "prefix_length", prefix_length
    l = l - prefix_length
    print "l", l
    rest = bs - prefix_length

    for unknown_block in range(l / bs):
        print unknown_block
        for i in range(bs):
            blocks.clear()

            for c in range(256):
                attempt = "A" * rest + "A" * (bs - i - 1) + unknown_string + chr(c)
                ctext = oracle(attempt)
                block = ctext.block(bs, unknown_block + 1).asHexString()
                blocks[block] = attempt

            input_data = "A" * rest + "A" * (bs - i - 1)
            ctext = oracle(input_data).block(bs, unknown_block + 1).asHexString()
            block = blocks[ctext]
            unknown_string += block[-1]

            if len(unknown_string) == l - padding:
                break

    print unknown_string
