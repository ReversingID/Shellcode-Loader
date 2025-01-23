# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

import random

# make sure n is 0 < n < m
rotl8 = lambda x,n: ((x << n) & 0xFF) | (x >> (8 - n))
rotr8 = lambda x,n: (x >> n) | ((x << (8 - n)) & 0xFF)

extract = lambda X: X & 0x1E
clear   = lambda X: X & 0xE1

cross = lambda L,R: (clear(L) | extract(R), clear(R) | extract(L))


with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# encode shellcode
if shlen % 2 == 1:
    shcode += b"\x90"
    shlen += 1

# generate single byte key
key = random.randrange(1,255)

# encode shellcode
enc_shcode = [key]
idx = 0
while idx < shlen:
    L = shcode[idx]
    R = shcode[idx + 1]

    L, R = cross(L, R)

    # extract the bits and replace
    enc_shcode.append(rotl8(L, 3) ^ key)
    enc_shcode.append(rotr8(R, 3) ^ key)
    
    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")