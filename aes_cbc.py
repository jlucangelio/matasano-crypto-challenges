import utils

with open("10.txt") as f:
    ciphertext = utils.ByteArray.fromBase64(f.read())
    print utils.aes_cbc_decrypt(ciphertext, utils.ByteArray.fromString("YELLOW SUBMARINE"),
                                iv=utils.ByteArray.fromHexString("00" * 16))