import glob
import sys
import re
import struct
from capstone import *

c_md = Cs(CS_ARCH_X86, CS_MODE_64)
c_md.detail = True
pattern_match = re.compile("\x48\x8b\x43\x10\x41\xbf\x30\x00\x00\x00", re.DOTALL) #Watchout for regex chars like $ (0x24)
pattern_match2 = re.compile("\x0f\x87....\x48\x8b\x43\x10", re.DOTALL)

def find_char_for_value(final_value, formula):
    found = False
    for i in xrange(0, 0xff):
        eval_ret = eval(str(i) + formula) & 0xFFFFFFFF
        if eval_ret == final_value :
            found = True
            return chr( (i-1)/2 )
    if not found:
        print "Solution find fail"

def extract_flags(filename):
    data = open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]

    if not poss:
        poss = [m.start() for m in re.finditer(pattern_match2, data)]
        if not poss:
            return ""

    passwd = ""
    for pos in poss:
        c = ""
        final_value = 0
        for d_i in c_md.disasm(data[pos:], 0x2000):
            #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
            if  d_i.mnemonic == "cmp":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                #c += int(d_i.op_str.split(", ")[1], 16)
                if len(d_i.bytes) == 8:
                    final_value = struct.unpack("<L", d_i.bytes[4:8])[0]
                    #print hex(final_value)
                elif len(d_i.bytes) == 5:
                    final_value = d_i.bytes[4]
                    if final_value > 0x80:
                        final_value += 0xFFFFFF00;
                    #print hex(final_value)
                else:
                    final_value = int(d_i.op_str.split(", ")[1], 16)
                break
            elif d_i.mnemonic == "lea" and d_i.op_str.split(", ")[0] == "rsi":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                x = d_i.bytes[3]
                if x & 0x80:
                    x = 0x100 - x
                    c += "-" + str(x) + " "
                else:
                    c += "+" + str(x) + " "
            elif d_i.mnemonic == "add":
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                c += "+" + str(int(d_i.op_str.split(", ")[1], 16)) + " "
            elif d_i.mnemonic == "sub":
                if d_i.op_str.split(", ")[0] == "rsp": continue
                #print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
                c += "-" + str(int(d_i.op_str.split(", ")[1], 16)) + " "
            else:
                continue
        ret = find_char_for_value(final_value, c)
        if not ret:
            print("0x%x:\t%s\t%s" % (d_i.address, d_i.mnemonic, d_i.op_str))
            sys.exit(-1)
        passwd += ret
        #break
    return passwd[::-1]

if __name__ == "__main__":
    #files_path = '.\\occult_dist\\'
    files_path = '.\\enlightenment_dist\\'
    files = glob.glob(files_path + '*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f.replace(files_path, '') + "@" + ret
        #break