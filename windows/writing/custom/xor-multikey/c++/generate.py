# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

stride = random.randrange(4,8)

with open("shellcode.bin", "rb") as f:
    shcode = f.read()

nblock  = len(shcode) // stride
remainder = len(shcode) % stride
idx_s   = 0

# padding
if remainder != 0:
    shcode = shcode + b"\x90"*(stride - remainder)
    nblock += 1

enc_shcode = [nblock, stride]

for idx_n in range(nblock):
    key = random.randrange(1, 255)

    enc_shcode += [key] + [ c ^ key for c in shcode[idx_s : idx_s + stride]]
    idx_s += stride

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")