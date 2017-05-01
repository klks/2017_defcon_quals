import glob
import sys
import re
from capstone import *

c_md = Cs(CS_ARCH_X86, CS_MODE_64)
c_md.detail = True
pattern_match = re.compile("\x48\x8B\x44\\\x24\x10\x48\x85\xC0\x0F\x84", re.DOTALL) #Watchout for regex chars like $ (0x24)

def extract_flags(filename):
    data = open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]

    if not poss:
        return ""

    passwd = ""
    for pos in poss:
        #print hex(pos)
        for d_i in c_md.disasm(data[pos:], 0x1000):
            if d_i.mnemonic == "cmp" and ( d_i.op_str.find('cl') != -1 or d_i.op_str.find('al') != -1):
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                passwd += chr(int(d_i.op_str.split(", ")[1], 16))
            elif d_i.mnemonic == "call":
                break
            else:
                continue
    return passwd

if __name__ == "__main__":
    #files_path = '.\\sorcery_dist\\'
    files_path = '.\\enlightenment_dist\\'
    files = glob.glob(files_path + '*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f.replace(files_path, '') + "@" + ret
        #break