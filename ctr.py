import utils

b64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
CIPHERTEXT = utils.ByteArray.fromBase64(b64)

plaintext = utils.aes_ctr_decrypt(CIPHERTEXT, "YELLOW SUBMARINE", 0)

print plaintext
print utils.aes_ctr_decrypt(utils.aes_ctr_decrypt(plaintext, "YELLOW SUBMARINE", 0),
							"YELLOW SUBMARINE", 0)
