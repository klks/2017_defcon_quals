import glob
import sys
import re

pattern_match = re.compile("\x48\x83\xff.\x74.\x50", re.DOTALL)

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]
    passwd = ""
    for pos in poss:
        passwd += data[pos+3]
    return passwd

if __name__ == "__main__":
    files = glob.glob('.\\enlightenment_dist\\*')
    for f in files:
        ret = extract_flags(f)
        if ret:
            print f + "@" + ret
        #break