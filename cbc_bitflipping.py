import utils

PREFIX = "comment1=cooking%20MCs;userdata="
SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon"

KEY = utils.ByteArray.random(utils.AES_BLOCKSIZE_BYTES)
IV = utils.ByteArray.random(utils.AES_BLOCKSIZE_BYTES)


def encrypt(data):
    plaintext = utils.ByteArray.fromString(PREFIX)
    escaped = data.split(";")[0].split("=")[0]
    if len(escaped) > 0:
        plaintext.extend(utils.ByteArray.fromString(escaped))
    plaintext.extend(utils.ByteArray.fromString(SUFFIX))

    plaintext.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)
    return utils.aes_cbc_encrypt(plaintext, KEY, IV)


def decrypt(ciphertext):
    plaintext = utils.aes_cbc_decrypt(ciphertext, KEY, IV)
    print plaintext
    items = str(plaintext).split(";")
    for item in items:
        k, v = item.split("=")
        if k == "admin" and v == "true":
            return True

    return False


# Byte 5
# Bit 0

print len(PREFIX)
print "from %x to %x" % (ord(":"), ord(";"))
print "from %x to %x" % (ord("<"), ord("="))

ciphertext = encrypt("aaaaa:admin<true")
ciphertext.bitwise_or(16 + 5, 0x1)
ciphertext.bitwise_or(16 + 11, 0x1)
print decrypt(ciphertext)
