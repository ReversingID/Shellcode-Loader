# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# shcode = "Archonlabs.ID"
# shlen  = len(shcode)

# encode the shellcode
key = random.randrange(2, 10)
enc_shcode = [key] + [0 for c in range(shlen)]

p = 1
s = [(key-1)*2, 0]

for i in range(0, key):
    j = i 
    idx = 0

    while j < shlen:
        enc_shcode[p] = shcode[j]

        if s[idx] > 0:
            j += s[idx]
            p += 1
        
        idx = (idx + 1) & 1
    
    s[0] -= 2
    s[1] += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
# print(",".join(c for c in enc_shcode), end='')
print(" }")
print(f"Length: {len(enc_shcode)}")