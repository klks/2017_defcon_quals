from pwn import *
import base64

dict_find = {}

data = open("flags.txt","rb").read().split("\n")
for d in data:
    d_hash, d_data = d.split("@")
    if d_hash not in dict_find:
        dict_find[d_hash] = d_data
    else:
        print "Dupe found"

context(arch = 'i386', os = 'linux')
r = remote('cm2k-sorcery_13de8e6bf26e435fc43efaf46b488eae.quals.shallweplayaga.me', 12002)
print r.recvline()

while 1:
    ret = r.recvline().strip()
    if ret not in dict_find:
        print ret
        r.interactive()
    else:
        r.send( dict_find[ret] + "\n" )