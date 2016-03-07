import utils

import ecb_cbc_detection


UNKNOWN_STRING = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

KEY = utils.ByteArray.random(16)


def oracle(input_data):
    input_ba = utils.ByteArray.fromString(input_data)
    input_ba.extend(utils.ByteArray.fromBase64(UNKNOWN_STRING))
    input_ba.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)

    ret = utils.aes_ecb_encrypt(input_ba, KEY)
    return ret


if __name__ == "__main__":
    bs = None
    padding = None

    l = len(oracle(""))
    for i in range(64):
        ctext = oracle("A" * (i+1))
        if len(ctext) != l:
            bs = len(ctext) - l
            padding = i
            break

    print "block size", bs
    print "padding", padding

    if ecb_cbc_detection.detect_ecb_cbc(oracle) != "ECB":
        print "Not ECB"

    unknown_string = ""
    blocks = {}

    for unknown_block in range(l / bs):
        print unknown_block
        for i in range(bs):
            blocks.clear()

            for c in range(256):
                attempt = "A" * (bs - i - 1) + unknown_string + chr(c)
                ctext = oracle(attempt)
                block = ctext.block(bs, unknown_block).asHexString()
                blocks[block] = attempt

            input_data = "A" * (bs - i - 1)
            ctext = oracle(input_data).block(bs, unknown_block).asHexString()
            block = blocks[ctext]
            unknown_string += block[-1]

            if len(unknown_string) == l - padding:
                break

    print unknown_string
