import utils

with open("6.txt") as f:
    contents = utils.ByteArray.fromBase64(f.read())
    # print contents.asBase64()

    normalized_edit_dists = {}
    min_edit_dist = 40 * 8
    for keysize in range(2, 41):
        edit_dist = utils.hamming_distance(contents[:keysize],
                                           contents[2*keysize:3*keysize]) / float(keysize)
        edit_dist2 = utils.hamming_distance(contents[keysize:2*keysize],
                                            contents[3*keysize:4*keysize]) / float(keysize)
        normalized_edit_dists[keysize] = (edit_dist + edit_dist2) / 2

    keysizes = sorted(normalized_edit_dists.iteritems(), key=lambda v: v[1])
    possible_keysizes = keysizes[:3]
    print "key sizes", possible_keysizes

    for possible_keysize, _ in possible_keysizes:
        transposed_blocks = [utils.ByteArray() for _ in range(possible_keysize)]

        for i, e in enumerate(contents):
            transposed_blocks[i % possible_keysize].append(e)

        possible_key = [utils.freq_analysis(block) for block in transposed_blocks]
        key = utils.ByteArray()
        for r in possible_key:
            if r[1] is None:
                break
            key.append(r[1])
        if len(key) < possible_keysize:
            continue

        print utils.repeating_xor(contents, key)
        break
