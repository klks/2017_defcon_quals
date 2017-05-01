import glob
import sys
import re
import base64
import struct

pattern_match = re.compile("\x48\x8b\x43\x10\x41\xbf\x30\x00\x00\x00", re.DOTALL)

def do_and_three_test(i, c):
    store = []

    cc = c.split(" ")[:-1]
    for ccc in cc:
        i = i + eval(ccc)
        print hex(i) + " " + bin(i)
        if (i&0x0F) & 3 == 0:
            print "HERE"
            store.append(i & 0xff)
    print repr(store)

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]

    passwd = ""
    for p in poss:
        new_p = p + 18
        c = ""
        while data[new_p:new_p+2] != "\x48\x81" and data[new_p:new_p+3] != "\x48\x83\x78":
            #print hex(new_p)
            if data[new_p] == "\x49":
                new_p += 4
            elif data[new_p] == "\xe8":
                new_p += 5
            elif data[new_p] == "\x48":
                if data[new_p+1] == "\x8b" or data[new_p+1:new_p+3] == "\x8d\x78":
                    new_p += 4
                elif data[new_p+1:new_p+3] == "\x8d\x05":
                    new_p += 7
                elif data[new_p+1:new_p+3] == "\x83\xee": #sub
                    #print "+ " + str(ord(data[new_p+3:new_p+4])),
                    #c += ord(data[new_p+3:new_p+4])
                    c += "-" + str(ord(data[new_p+3:new_p+4])) + " "
                    new_p += 4
                elif data[new_p+1:new_p+3] == "\x83\xc6": #add
                    #print "- " + str(ord(data[new_p+3:new_p+4])),
                    #c -= ord(data[new_p+3:new_p+4])
                    c += "+" + str(ord(data[new_p+3:new_p+4])) + " "
                    new_p += 4
                elif data[new_p+1] == "\xb8":
                    new_p += 10
                    continue
                else:
                    print repr(data[new_p:new_p+3])
                    print filename + " => Unknown 0x48 opcode " + hex(ord(data[new_p+1:new_p+2])) + " at " + hex(new_p)
                    sys.exit(-1)
            else:
                print repr(data[new_p:new_p+3])
                print filename + " => Unknown opcode " + hex(ord(data[new_p:new_p+1])) + " at " + hex(new_p)
                sys.exit(-1)

        if data[new_p:new_p+2] == "\x48\x81":
            #print hex(p) + " => "+ hex(struct.unpack("<L", data[new_p+4:new_p+8])[0] + c)
            final_value = struct.unpack("<L", data[new_p+4:new_p+8])[0]
        elif data[new_p:new_p+3] == "\x48\x83\x78":
            #print hex(p) + " => "+ hex(ord(data[new_p+4]) + c)
            final_value = ord(data[new_p+4])
            if final_value > 0x80:
                final_value += 0xFFFFFF00;
        #print hex(p) + " Final Value => " + hex(final_value) + " eval(c) => " + hex(eval(c)) + " [" + c + "]"
        found = False
        for i in xrange(0, 0xff):
            if eval(str(i) + c) & 0xFFFFFFFF == final_value :
                found = True
                #print hex(p) + " " + hex(i)
                passwd += chr( (i-1)/2 )
        if not found:
            print "Solution find fail"
            sys.exit(-1)
        #break
        #print ""
    return passwd
    
if __name__ == "__main__":
    files = glob.glob('.\\occult_dist\\*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f + "@" + ret
        #break  