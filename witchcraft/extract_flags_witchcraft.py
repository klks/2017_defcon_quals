import glob
import sys
import re
import base64

pattern_match = re.compile("\x55\x48\x89\xE5\x48\x85\xFF", re.DOTALL)

def extract_flags(filename):
    data =  open(filename, "rb").read()
    #print data.find(pattern_match)
    poss = [m.start() for m in re.finditer(pattern_match, data)]

    passwd = ""
    for p in poss:
        new_p = p
        new_p += 7
        c = 0
        while data[new_p] != "\x5D":
            #print hex(new_p)
            if data[new_p] == "\x0F":   #this is some sort of jump, ignore
                new_p += 6
            elif data[new_p] == "\x70" or data[new_p] == "\x75": #Jump
                new_p += 2
            elif data[new_p:new_p+2] == "\x48\x83":
                if data[new_p+2] == "\xef": #Sub instr
                    c += ord(data[new_p+3:new_p+4])
                elif data[new_p+2] == "\xc7": #Add instruction
                    c -= ord(data[new_p+3:new_p+4])
                elif data[new_p+2] == "\xff":  #cmp
                    pass
                else:
                    print filename + " => Unknown add/sub opcode " + hex(ord(data[new_p:new_p+1])) + " at " + hex(new_p)
                    sys.exit(-1)
                new_p += 4
            elif data[new_p:new_p+2] == "\x48\x81": #add rax/cmp edi
                new_p += 7
            elif data[new_p:new_p+2] == "\x48\x85":
                new_p += 3
            elif data[new_p:new_p+2] == "\x31\xc0":
                new_p += 2
            elif data[new_p] == "\xb8": #mov eax
                c += ord(data[new_p+1])
                new_p += 5
            elif data[new_p:new_p+2] == "\x48\xC7":
                c += ord(data[new_p+3])
                new_p += 7
            else:
                print repr(data[new_p:new_p+3])
                print filename + " => Unknown opcode " + hex(ord(data[new_p:new_p+1])) + " at " + hex(new_p)
                sys.exit(-1)
        passwd += chr(c & 0xff)
    #print passwd
    return passwd

if __name__ == "__main__":
    files = glob.glob('.\\witchcraft_dist\\*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f + "@" + ret
        #break