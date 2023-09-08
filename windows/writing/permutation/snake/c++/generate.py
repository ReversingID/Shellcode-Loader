# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# encode the shellcode
# how many row?
rows = random.randrange(2, 5)

remainder = shlen % rows
if remainder > 0:
    extra = (rows - remainder)

    shlen += extra
    shcode += b"\x00" * extra    

cols = shlen // rows
enc_shcode = [rows]

for r in range(0, rows):
    start = r * cols 
    end   = (r + 1) * cols
    
    shrow = shcode[start:end]

    if r % 2 == 1:
        enc_shcode += shrow[::-1]
    else:
        enc_shcode += shrow

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")
print(f"Length: {len(enc_shcode)}")