import base64
import binascii

hex2binstr = binascii.unhexlify

def hex2bytearray(hexstring):
    return bytearray.fromhex(hexstring)

def hex2base64(hexstring):
    binstr = hex2binstr(hexstring)
    return base64.b64encode("".join(binstr))

def bytearray2hex(ba):
    return "".join(["%x" % b for b in ba])

def bytearray2str(ba):
    return ba.decode()

def fixed_xor(plaintext, key):
    bplaintext = hex2bytearray(plaintext)
    bkey = hex2bytearray(key)

    res = bytearray()
    for i, byte in enumerate(bplaintext):
        res.append(byte ^ bkey[i])

    return res

def freq_analysis(string):
    max_count = 0
    candidate = None
    for char in range(256):
        key = ("%x" % char) * len(string)
        res = fixed_xor(string, key)
        count = 0
        for b in res:
            c = chr(b)
            if "a" <= c <= "z" or "A" <= c <= "Z":
                count += 1
                if c in "etaoinshrETAOINSHR":
                    count += 1
            else:
                count -= 1

        if count > max_count:
            max_count = count
            candidate = res

    print candidate

if __name__ == "__main__":
    hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    base64str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    print hex2bytearray(hexstring)

    b64res = hex2base64(hexstring)
    print "hex2base64", b64res == base64str

    plaintext = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    fixed_xor_result = "746865206b696420646f6e277420706c6179"
    print "fixed_xor", bytearray2hex(fixed_xor(plaintext, key)) == fixed_xor_result

    freq_analysis("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

