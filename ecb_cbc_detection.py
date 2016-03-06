import utils

import Crypto.Random.random as random


def random_key(nbytes):
    return utils.ByteArray.random(nbytes)


def encryption_oracle(input_data):
    key = random_key(16)
    prefixlen = random.randint(5, 10)
    suffixlen = random.randint(5, 10)
    prefix = utils.ByteArray.random(prefixlen)
    suffix = utils.ByteArray.random(suffixlen)

    input_ba = utils.ByteArray.fromString(input_data)
    input_ba.prepend(prefix)
    input_ba.extend(suffix)
    input_ba.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)

    iv = utils.ByteArray.random(utils.AES_BLOCKSIZE_BYTES)

    if random.randint(0, 1) == 0:
        print "using ECB"
        ret = utils.aes_ecb_encrypt(input_ba, key)
    else:
        print "using CBC"
        ret = utils.aes_cbc_encrypt(input_ba, key, iv)

    return ret


def detect_ecb_cbc(oracle):
    hexstring = "00" * utils.AES_BLOCKSIZE_BYTES * 6
    ciphertext = oracle(hexstring)

    block_count = {}
    for block_index in range(ciphertext.nblocks(utils.AES_BLOCKSIZE_BYTES)):
        block = ciphertext.block(utils.AES_BLOCKSIZE_BYTES, block_index).asHexString()
        if block in block_count:
            block_count[block] += 1
        else:
            block_count[block] = 1

    for v in block_count.values():
        if v > 1:
            return "ECB"

    return "CBC"


if __name__ == "__main__":
    key = random_key(16).asHexString()
    print len(key) / 2, key

    print encryption_oracle("subidubisubidubi")
    print

    for i in range(10):
        print detect_ecb_cbc(encryption_oracle)
        print
