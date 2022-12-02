# to use shamir shards
 1. set `database_password=sss` (otherwise passwords will be used verbatim)
 1. once `pykmip` server started:
```
# enter the container
telnet localhohost 5066
# type the shard followed by enter
# get operators to do the same thing until the number of threshold is reached
# type commit
```
# to rekey (re-password actually) of backend database
 1. make sure `pykmip` server is stopped
 1. `./rekey-server.py --database /data/db/pykmip.db -gpg=[u1],[u2],..,[un] -t [threshold, default=2]` and follow the procedure above
   where [u1]...[un] are the gpg public key files. we need t/n to unlock the database
