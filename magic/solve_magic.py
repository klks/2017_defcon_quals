import glob
import sys
import re

pattern_match = re.compile("\x74\x0e\x48\x83\xec\x08\xbf")

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = [m.start() for m in re.finditer(pattern_match, data)]
    passwd = ""
    for pos in poss:
        #print hex(pos)
        passwd += data[pos-1:pos]
    return passwd

if __name__ == "__main__":
    files = glob.glob('.\\magic_dist\\*')
    for f in files:
        print f + "@" + extract_flags(f)