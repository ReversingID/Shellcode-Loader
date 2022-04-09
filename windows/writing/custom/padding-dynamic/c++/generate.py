# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# encode the shellcode
idx = 0
enc_shcode = []

while idx < shlen:
    # generate padding number in the range of (2..4)
    pad = random.randrange(2, 5)
    remainder = shlen - idx 

    if pad > remainder:
        pad = remainder 

    enc_shcode.append(pad)
    enc_shcode += shcode[idx:idx+pad]
    idx += pad

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")
print(f"Length: {len(enc_shcode)}")