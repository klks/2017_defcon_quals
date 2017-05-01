import glob
import sys
import re
import struct
from capstone import *

c_md = Cs(CS_ARCH_X86, CS_MODE_64)
c_md.detail = True
pattern_match = re.compile("\x42\x8A\x44.\x0C\x88", re.DOTALL) #Watchout for regex chars like $ (0x24)
pattern_match2 = re.compile("\x48...\x74.\x48..\x75.\xbf", re.DOTALL)

def find_marker(data):
    poss = [m.start() for m in re.finditer(pattern_match, data)]
    poss2 = [m.start() for m in re.finditer(pattern_match2, data)]

    if poss2 and poss:
        return poss2+poss
    if poss: return poss
    if poss2: return poss2
    return None

def extract_flags(filename):
    data = open(filename, "rb").read()

    poss = find_marker(data)
    if not poss:
        print "Unable to process => " + filename
        return ""

    #print filename + " => " + repr(poss)
    passwd = ""
    for pos in poss:
        #print hex(pos)
        ignore_register = []
        for d_i in c_md.disasm(data[pos:], 0x2000):
            #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
            if  d_i.mnemonic == "call":
                break
            elif d_i.mnemonic == "test":
                x = d_i.op_str.split(", ")[1]
                if x not in ignore_register:
                    ignore_register.append(x)
            elif d_i.mnemonic == "cmp" and d_i.op_str.split(", ")[0] not in ["r15d", "r14d", "r12d"]:
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                if d_i.op_str.split(", ")[0] in ignore_register: continue
                x = chr(int(d_i.op_str.split(", ")[1],16))
                if ord(x) >= 0x20 and ord(x) <= 0x7e:
                    passwd += x
        #break
    return passwd

if __name__ == "__main__":
    #files_path = '.\\alchemy_dist\\'
    files_path = '.\\enlightenment_dist\\'
    files = glob.glob(files_path + '*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f.replace(files_path, '') + "@" + ret
        #break