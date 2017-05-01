from pwn import *
import base64
import sys

dict_find = {}

data = open("flags.txt","rb").read().split("\n")
for d in data:
    try:
        d_hash, d_data = d.split("$")
    except:
        print d
        sys.exit(-1)
    if d_hash not in dict_find:
        dict_find[d_hash] = d_data
    else:
        print "Dupe found"

context(arch = 'i386', os = 'linux')
r = remote('cm2k-witchcraft_5f60e994e19a100de1dee736608d639f.quals.shallweplayaga.me', 12003)
print r.recvline()

line_to_send = ""
while 1:
    ret = r.recvline().strip()
    if ret not in dict_find:
        print ret
        print "=> " + line_to_send
        break
        #r.interactive()
    else:
        line_to_send = ret + " => " + dict_find[ret]
        r.send( base64.b64encode(dict_find[ret]) + "\n" )