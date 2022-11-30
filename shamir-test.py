from binascii import hexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir

nonce=b'123456'
key = get_random_bytes(16)
shares = Shamir.split(2, 5, key)
for idx, share in shares:
  print("Index #%d: %s" % (idx, hexlify(share)))

with open("clear.txt", "rb") as fi, open("enc.txt", "wb") as fo:
  cipher = AES.new(key, AES.MODE_EAX)
  ct, tag = cipher.encrypt(fi.read()), cipher.digest()
  fo.write(nonce + tag + ct)
