import os

def delete_file(filename):
    try:
        os.remove(".\\enlightenment_dist\\" + filename)
    except:
        print "Error deleting => " + filename
        pass

flags =  open("alchemy.txt", "rb").read().split("\n")
for f in flags:
    x = f.split("@")
    delete_file(x[0])

flags =  open("sorcery.txt", "rb").read().split("\n")
for f in flags:
    x = f.split("@")
    delete_file(x[0])

flags =  open("occult.txt", "rb").read().split("\n")
for f in flags:
    x = f.split("@")
    delete_file(x[0])
    
flags =  open("magic.txt", "rb").read().split("\n")
for f in flags:
    x = f.split("@")
    delete_file(x[0])
    
flags =  open("witchcraft.txt", "rb").read().split("\n")
for f in flags:
    x = f.split("@")
    delete_file(x[0])
    