import utils
from Crypto.Cipher import AES

obj = AES.new("YELLOW SUBMARINE", AES.MODE_ECB, "")
# plaintext = obj.decrypt(message)

# with open("7.txt") as f:
#     ba = utils.ByteArray.fromBase64(f.read())
#     plaintext = obj.decrypt(str(ba))
#     print plaintext

with open("8.txt") as f:
    for line_index, line in enumerate(f.readlines()):
        line = line.strip()

        blocks = {}
        for i in range(len(line) / 2 / 8):
            block = line[16*i:16*(i+1)]
            if block not in blocks:
                blocks[block] = 0
            blocks[block] += 1

            if blocks[block] > 1:
                print line_index, block

        # print blocks
