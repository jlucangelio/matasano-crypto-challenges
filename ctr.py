import utils

b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
CIPHERTEXT = utils.ByteArray.fromBase64(b64)

p = utils.aes_ctr_encrypt(CIPHERTEXT, utils.ByteArray.fromString("YELLOW SUBMARINE"), 0)
print repr(p.asString())
print len(p)
