import utils

from collections import OrderedDict


KEY = utils.ByteArray.random(16)


def parse(s):
    res = OrderedDict()
    fields = s.split("&")
    for field in fields:
        k, v = field.split("=")
        res[k] = v
    return res


def unparse(d):
    res = []
    for k in d:
        v = d[k]
        if type(v) == str and ("=" in v or "&" in v):
            continue
        res.append("%s=%s" % (k, v))
    return "&".join(res)


def profile_for(email):
    return unparse(OrderedDict([("email", email), ("uid", 10), ("role", "user")]))


def encrypt_profile(email):
    ptext = utils.ByteArray.fromString(profile_for(email))
    ptext.pkcs7pad(utils.AES_BLOCKSIZE_BYTES)
    return utils.aes_ecb_encrypt(ptext, KEY)


def decrypt_profile(p):
    ptext = utils.aes_ecb_decrypt(p, KEY).asString()
    last_byte = ord(ptext[-1])
    if last_byte >= 1 and last_byte <= 15:
        ptext = ptext[:-last_byte]
    return parse(ptext)


if __name__ == "__main__":
    s = "foo=bar&baz=qux&zap=zazzle"
    print parse(s)
    print s == unparse(parse(s))

    print "profile_for", profile_for("foo@bar.com") == "email=foo@bar.com&uid=10&role=user"
    print decrypt_profile(encrypt_profile("foo@bar.com"))

    # len("email=foo@bar.co") == 16
    first_block = "foo@bar.co"
    role = "admin"
    nbytes = 16 - len(role)
    ptext = role + (chr(nbytes) * nbytes)
    print repr(ptext), len(ptext)
    admin_block = encrypt_profile(first_block + ptext).blocksAsHexStrings(16)[1]

    # "email=username@domain.com&uid=10&role=" + "admin" + padding
    ptext = "email=@bar.com&uid=10&role="
    s = "A" * (16 - (len(ptext) % 16))
    print s, len(s + ptext)
    blocks = encrypt_profile(s + "@bar.com").blocksAsHexStrings(16)

    p = blocks[:-1] + [admin_block]
    print decrypt_profile(utils.ByteArray.fromHexString("".join(p)))
