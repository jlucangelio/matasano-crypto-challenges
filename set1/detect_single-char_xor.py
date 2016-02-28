import utils

with open("4.txt") as f:
    candidate = None
    max_count = 0
    for line in f.readlines():
        decrypted, count = utils.freq_analysis(line.strip())
        # if count > 0:
            # print decrypted, count
        if count > max_count:
            max_count = count
            candidate = decrypted

    print candidate
