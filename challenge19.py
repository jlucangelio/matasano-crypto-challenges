import utils

CIPHERTEXTS = []
NONCE = 0
KEY = utils.ByteArray.random(utils.AES_BLOCKSIZE_BYTES)

with open("challenge19.txt") as f:
   for i, line in enumerate(f.readlines()):
        # print line.strip()
        plaintext = utils.ByteArray.fromBase64(line.strip())
        CIPHERTEXTS.append(utils.aes_ctr_encrypt(plaintext, KEY, NONCE))

# print CIPHERTEXTS

byte_count = {}
max_count = 0
max_byte = None

for c in CIPHERTEXTS:
    for byte in c:
        if byte not in byte_count:
            byte_count[byte] = 0

        byte_count[byte] += 1

        if byte_count[byte] > max_count:
            max_count = byte_count[byte]
            max_byte = byte

byte_counts = byte_count.items()
print sorted(byte_counts, key=lambda p: p[1])
print len(byte_counts)
print

# print byte_count
print max_byte

substitutions = {}
substitutions[max_byte] = 'e'

print substitutions
