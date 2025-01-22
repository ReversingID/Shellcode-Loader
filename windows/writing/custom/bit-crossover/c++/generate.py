# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

import random 

# make sure n is 0 < n < 8
rotl8 = lambda x,n: ((x << n) & 0xFF) | (x >> (8 - n))
rotr8 = lambda x,n: (x >> n) | ((x << (8 - n)) & 0xFF)

high  = lambda x: x & 0xF0
low   = lambda x: x & 0x0F

cross = lambda L,R: (high(L) | low(R), high(R) | low(L))


with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# generate single byte key
key = random.randrange(1,255)

# make sure shellcode is even-length
if shlen % 2 == 1:
    shcode += b"\x90"
    shlen  += 1

# encode shellcode
enc_shcode = [key]
idx = 0
while idx < shlen:
    L = shcode[idx    ]     # LEFT
    R = shcode[idx + 1]     # RIGHT

    # get half of each byte and cross
    L, R = cross(L, R)

    # rotate then XOR
    enc_shcode.append(rotl8(L, 3) ^ key)
    enc_shcode.append(rotr8(R, 3) ^ key)

    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")