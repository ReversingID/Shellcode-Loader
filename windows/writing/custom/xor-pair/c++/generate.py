# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

if shlen % 2 == 1:
    shcode += b"\x90"
    shlen += 1

# encode shellcode
enc_shcode = []
idx = 0
while idx < shlen:
    key = shcode[idx]

    enc_shcode.append(key)
    enc_shcode.append(key ^ shcode[idx + 1])
    
    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")