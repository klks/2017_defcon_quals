import glob
import sys
import re
import base64
import string

pattern_match = "\x42\x8A\x44\x25\x0C"

def strategy2_extract(data):
    pattern_match_2 = re.compile("\x0f\xb6..\x48\x83", re.DOTALL)
    poss = [m.start() for m in re.finditer(pattern_match_2, data)]
    passwd = ""
    for p in poss:
        c = data[p+7:p+8]
        if c in string.printable:
            passwd += c

    pattern_match_2 = re.compile("\x0f\xb6.\x48\x83", re.DOTALL)
    poss = [m.start() for m in re.finditer(pattern_match_2, data)]
    for p in poss:
        c = data[p+6:p+7]
        if c in string.printable:
            passwd = c + passwd
    return passwd

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = data.find(pattern_match)
    if poss == -1:
        return strategy2_extract(data)

    poss += 36

    passwd = ""
    while 1:
        if data[poss] == "\x48":
            passwd += data[poss+3:poss+4]
            poss += 24
        else:
            break   
    return passwd

if __name__ == "__main__":
    files = glob.glob('.\\alchemy_dist\\*')
    for f in files:
        ret = extract_flags(f)
        if ret:
        	print f + "@" + ret#base64.b64encode(ret)