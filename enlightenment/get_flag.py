from pwn import *
import base64

dict_find = {}

data = open("flags.txt","rb").read().split("\n")
#print repr(data)
for d in data:
    d_hash, d_data = d.split("@")
    if d_hash not in dict_find:
        dict_find[d_hash] = d_data
    else:
        print "Dupe found"

context(arch = 'i386', os = 'linux')
r = remote('cm2k-enlightenment_4ee3a7c97ce496cde9bdf905843cf0f1.quals.shallweplayaga.me', 12999)
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