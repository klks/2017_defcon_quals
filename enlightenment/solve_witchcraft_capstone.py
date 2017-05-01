import glob
import sys
import re
from capstone import *

c_md = Cs(CS_ARCH_X86, CS_MODE_64)
c_md.detail = True
pattern_match = re.compile("\x55\x48\x89\xE5\x48\x85\xFF", re.DOTALL) #Watchout for regex chars like $ (0x24)

def extract_flags(filename):
    data = open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]

    if not poss:
        return ""

    passwd = ""
    for pos in poss:
        #print hex(pos)
        c = 0
        for d_i in c_md.disasm(data[pos:], 0x2000):
            #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
            if d_i.mnemonic == "add":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                c -= int(d_i.op_str.split(", ")[1], 16)
            elif d_i.mnemonic == "sub":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                c += int(d_i.op_str.split(", ")[1], 16)
            elif  d_i.mnemonic == "cmp":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                c += int(d_i.op_str.split(", ")[1], 16)
            elif d_i.mnemonic == "ret":
                break
            else:
                continue
        passwd += chr(c & 0xff)
        #break
    return passwd

if __name__ == "__main__":
    #files_path = '.\\witchcraft_dist\\'
    files_path = '.\\enlightenment_dist\\'
    files = glob.glob(files_path + '*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f.replace(files_path, '') + "@" + ret
        #break