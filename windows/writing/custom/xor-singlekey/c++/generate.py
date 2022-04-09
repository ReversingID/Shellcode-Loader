# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()

# generate single byte key
key = random.randrange(1, 255)

# xor-encrypt
enc_shcode = [key] + [ c ^ key for c in shcode ]

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")