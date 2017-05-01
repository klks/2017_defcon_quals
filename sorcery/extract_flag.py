import glob
import sys
import re
import base64

pattern_match = "\x48\x8b\x44\x24\x10\x48\x85\xc0\x0f\x84"

def extract_flags(filename):
    data =  open(filename, "rb").read()
    poss = data.find(pattern_match)
    if poss == -1:
        print "Unable to find pattern"
        sys.exit(-1)
    poss += 20

    passwd = ""
    while 1:
        if data[poss] == "\x80":
            passwd += data[poss+2:poss+3]
            poss += 22
        elif data[poss-1] == "\x85":
            passwd += data[poss-3:poss-2]
            break
        else:
            break   
    return passwd

if __name__ == "__main__":
    files = glob.glob('.\\sorcery_dist\\*')
    for f in files:
        print f + "@" + base64.b64encode(extract_flags(f))
        #break