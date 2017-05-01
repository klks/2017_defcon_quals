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
r = remote('cm2k-magic_b46299df0752c152a8e0c5f0a9e5b8f0.quals.shallweplayaga.me', 12001)
print r.recvline()

while 1:
    ret = r.recvline().strip()
    if ret not in dict_find:
        print ret
        r.interactive()
    else:
        encoded_flag = base64.b64encode(dict_find[ret]) + "\n"
        print repr(encoded_flag)
        r.send( encoded_flag )