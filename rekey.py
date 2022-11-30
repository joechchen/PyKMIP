#!/usr/bin/env python3
import OpenSSL.crypto, argparse, re , sys, random, os.path, binascii, gnupg
from sqlcipher3 import dbapi2 as sqlcipher
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
gpg = gnupg.GPG()
from getpass import getpass

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Rekeying sqlite backend using a random string and nonce.')
  parser.add_argument('--database', help='sqlite database to be rekeyed;', default='/data/db/pykmip.db')
  #parser.add_argument('-s','--shards', help='number of shards', required=True)
  parser.add_argument('-g','--gpg', help='comma-separtated gpg public key files against which to encrypt shards, at lest two for obvious reason;', required=True)
  parser.add_argument('-t','--threshold', help='threshold to unlock (default 2)', type=int, choices=range(2, 10) ,default=2)
  parser.add_argument('-p','--password', help='in case password is known -- bypassing SSS')
  parser.add_argument('-P','--printpass',help='print out new password (USED ONLY IN DEBUG)',action='store_true')
  parser.add_argument('-i','--init',help='create encrypted database from plain database.',action='store_true')
  args = parser.parse_args()
  db = sqlcipher.connect(args.database)
  if not args.password: # we need shards
    shares = []
    for i in range(args.threshold):
      sh = getpass(f'Please input shard #{i}:').split(',')
      shares.append((int(sh[0]), binascii.unhexlify(sh[1])))
    
    pwb = Shamir.combine(shares)
    pw=binascii.hexlify(pwb).decode('ascii')
    db.execute(f"pragma key='{pw}';")
  else: 
    db.execute(f"pragma key='{args.password}';")

  try:
    db.execute('select * from sqlite_master;').fetchall()
  except sqlcipher.Error as er:
    print('SQLite error: %s' % (' '.join(er.args)))
    sys.exit(1)
  
   
  if args.init: # starting from plaintext database
    o=re.sub('.db','-rekeyed.db',args.database)
    if os.path.exists(o):
      print("File '%s' exists, please delete it and run rekey again." % o)
      sys.exit(1)

  s=args.gpg.split(',')
  pwb = get_random_bytes(16) # binary 
  pw=binascii.hexlify(pwb).decode('ascii')
  shares = Shamir.split(args.threshold,len(s), pwb)
  # force start gpg-agent? otherwise can't scan key
  for i in range(len(s)):
    gpg.import_keys_file(s[i])
    rec=gpg.scan_keys(s[i])[0]['keyid']
    t=str(shares[i][0]).encode('ascii')+','.encode('ascii')+binascii.hexlify(shares[i][1])
    x=gpg.encrypt(t,rec,always_trust=True, armor=True,extra_args=['--recipient-file',s[i]])
    print(x)

  if args.init: # starting from plaintext database
    db.execute(f"ATTACH DATABASE '{o}' AS encrypted KEY '{pw}'")
    db.execute("SELECT sqlcipher_export('encrypted');")
    db.execute("DETACH DATABASE encrypted;")
  else: # simply rekey
    db.execute(f"pragma rekey='{pw}'")

  if args.printpass:
    print("New password: '%s' YOU REALLY SHOUDN'T BE DOING THIS!!!" % pw)

  #db.execute('select * from managed_objects;').fetchall()
