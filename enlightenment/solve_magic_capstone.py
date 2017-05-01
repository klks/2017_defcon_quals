import glob
import sys
import re
from capstone import *

c_md = Cs(CS_ARCH_X86, CS_MODE_64)
c_md.detail = True
pattern_match = re.compile("\x48\x83\xff.\x74\x0e\x48\x83\xec\x08\xbf", re.DOTALL)
pattern_match2 = re.compile("\x48\x83\xff.\x74.\x50", re.DOTALL)

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]
    
    if not poss:
        poss = [m.start() for m in re.finditer(pattern_match2, data)]
        if not poss:
            return ""

    passwd = ""
    for pos in poss:
        #print hex(pos)
        for d_i in c_md.disasm(data[pos:], 0x1000):
            if d_i.mnemonic == "cmp" and d_i.op_str.find('rdi') != -1:
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                passwd += chr(int(d_i.op_str.split(", ")[1], 16))
            elif d_i.mnemonic == "push" and d_i.op_str == "rdi":
                break
            else:
                continue
        break   ##we only need the first instance
    return passwd

if __name__ == "__main__":
    #files_path = '.\\magic_dist\\'
    files_path = '.\\enlightenment_dist\\'
    files = glob.glob(files_path + '*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f.replace(files_path, '') + "@" + ret
        #break