import utils

with open("4.txt") as f:
    candidate = None
    max_count = 0
    for line in f.readlines():
        decrypted, key, count = utils.freq_analysis(utils.ByteArray.fromHexString(line.strip()))
        if count > max_count:
            max_count = count
            candidate = decrypted

    print candidate
