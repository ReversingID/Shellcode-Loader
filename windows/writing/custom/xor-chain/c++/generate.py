# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

import random 

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

key = random.randrange(1, 255)

# encode shellcode
enc_shcode = [key]

idx = 0
while idx < shlen:
    enc_shcode.append(shcode[idx] ^ enc_shcode[idx])
    idx += 1

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")