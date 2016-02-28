import base64
import binascii


SET_BITS = {
    0x0: 0, # 0000
    0x1: 1, # 0001
    0x2: 1, # 0010
    0x3: 2, # 0011
    0x4: 1, # 0100
    0x5: 2, # 0101
    0x6: 2, # 0110
    0x7: 3, # 0111
    0x8: 1, # 1000
    0x9: 2, # 1001
    0xa: 2, # 1010
    0xb: 3, # 1011
    0xc: 2, # 1100
    0xd: 3, # 1101
    0xe: 3, # 1110
    0xf: 4, # 1111
}


class ByteArray(object):
    @classmethod
    def fromHexString(cls, hexstring):
        e = cls()
        e.ba = bytearray.fromhex(hexstring)
        return e

    @classmethod
    def fromBase64(cls, b64string):
        pass

    @classmethod
    def fromString(cls, string):
        e = cls()
        e.ba = bytearray(string)
        return e

    def __init__(self):
        self.ba = bytearray()

    def __eq__(self, other):
        return self.ba == other.ba

    def __ne__(self, other):
        return self.ba != other.ba

    def __str__(self):
        return self.ba.decode()

    def asHexString(self):
        return "".join(["%02x" % b for b in self.ba])

    def asBase64(self):
        return base64.b64encode("".join(str(self)))

    def __len__(self):
        return len(self.ba)

    def __getitem__(self, key):
        return self.ba[key]

    def __setitem__(self, key, value):
        self.ba[key] = value

    def __iter__(self):
        return self.ba.__iter__()

    def iterkeys(self):
        return self.__iter__()

    def append(self, e):
        self.ba.append(e)


def fixed_xor(plaintext, key):
    res = ByteArray()
    for i, byte in enumerate(plaintext):
        res.append(byte ^ key[i])

    return res


def repeating_xor(bplaintext, skey):
    q = len(bplaintext) // len(skey)
    r = len(bplaintext) % len(skey)
    full_key = skey * q + skey[:r]
    return fixed_xor(bplaintext, ByteArray.fromString(full_key))


def freq_analysis(string):
    max_count = 0
    candidate = None
    for char in range(256):
        key = ("%x" % char) * len(string)
        res = fixed_xor(ByteArray.fromHexString(string), ByteArray.fromHexString(key))
        count = 0
        for b in res:
            c = chr(b)
            if "a" <= c <= "z" or "A" <= c <= "Z":
                count += 1
                if c in "etaoinshrETAOINSHR":
                    count += 1
            elif c == " " or c == "'":
                pass
            else:
                count -= 2

        if count > max_count:
            max_count = count
            candidate = res

    return candidate, max_count


def set_bits(b):
    return SET_BITS[b & 0xF] + SET_BITS[(b & 0xF0) >> 4]


def hamming_distance(string1, string2):
    count = 0
    ba1 = ByteArray.fromString(string1)
    ba2 = ByteArray.fromString(string2)

    xored = fixed_xor(ba1, ba2)
    for b in xored:
        count += set_bits(b)

    return count


if __name__ == "__main__":
    hexstring = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    print ByteArray.fromHexString(hexstring).asBase64()

    b64res = ByteArray.fromHexString(hexstring).asBase64()
    print "hex2base64", b64res == b64str

    plaintext = ByteArray.fromHexString("1c0111001f010100061a024b53535009181c")
    key = ByteArray.fromHexString("686974207468652062756c6c277320657965")
    fixed_xor_result = ByteArray.fromHexString("746865206b696420646f6e277420706c6179")
    print "fixed_xor", fixed_xor(plaintext, key) == fixed_xor_result

    print freq_analysis("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0]

    line = ByteArray.fromString("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    res = repeating_xor(line, "ICE").asHexString()
    print "repeating_xor", res == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    print set_bits(0), set_bits(0x1), set_bits(0x0A), set_bits(0x78), set_bits(0xF8)
    print "hamming_distance", hamming_distance("this is a test", "wokka wokka!!!") == 37
