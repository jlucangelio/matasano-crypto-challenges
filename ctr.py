import utils

b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
CIPHERTEXT = utils.ByteArray.fromBase64(b64)

print utils.aes_ctr_decrypt(CIPHERTEXT, "YELLOW SUBMARINE", 0)
