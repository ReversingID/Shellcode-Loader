# read shellcode from `shellcode.bin` and
# generate the encoded shellcode 

# make sure n is 0 < n < m
rotl8 = lambda x,n: ((x << n) & 0xFF) | (x >> (8 - n))
rotr8 = lambda x,n: (x >> n) | ((x << (8 - n)) & 0xFF)

rotl16 = lambda x,n: ((x << n) & 0xFFFF) | (x >> (16 - n))
rotr16 = lambda x,n: (x >> n) | ((x << (16 - n)) & 0xFFFF)

make_word = lambda L,R: (L << 8) | R


with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# encode shellcode
if shlen % 2 == 1:
    shcode += b"\x90"
    shlen += 1

# encode shellcode
enc_shcode = []
idx = 0
while idx < shlen:
    L = shcode[idx]
    R = shcode[idx + 1]

    # byte-level rotation
    L = rotl8(L, 3)
    R = rotr8(R, 7)

    # word-level rotation 
    W = make_word(L, R)
    W = rotr16(W, 5)

    # split word into byte
    enc_shcode.append((W >> 8) & 0xFF)
    enc_shcode.append(W & 0xFF)
    
    idx += 2

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")