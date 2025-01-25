# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()

# generate single byte key
seed = random.randrange(1, 255)

# xor-encrypt
enc_shcode = [seed]

state = seed
taps  = [8, 6, 5, 4]
for c in shcode:
    # generate value from LFSR 
    feedback = 0
    for tap in taps:
        feedback ^= (state >> (tap - 1)) & 1

    feedback ^= (state ^ (state >> 3)) & 1
    state = ((state << 1) | feedback) & 0xFF

    # XOR with shellcode byte
    enc_shcode.append(c ^ state)

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")

print(f"Length: {len(enc_shcode)}")