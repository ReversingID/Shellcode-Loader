# read shellcode from `shellcode.bin` and 
# generate the encoded shellcode

import random

with open("shellcode.bin", "rb") as f:
    shcode = f.read()
shlen = len(shcode)

# encode the shellcode
# how many row?
rows = random.randrange(2, 5)
enc_shcode = [rows]

remainder = shlen % rows
if remainder > 0:
    extra = (rows - remainder)

    shlen += extra
    shcode += b"\x00" * extra    

cols = shlen // rows

matrix = []
for r in range(0, rows):
    start = r * cols 
    end   = (r + 1) * cols

    matrix.append(shcode[start:end])

# direction 
#   0 -> right
#   1 -> down
#   2 -> left
#   3 -> up
direction = 0

top = 0
bottom = rows-1
left = 0
right = cols-1 

print(f"rows={rows} | cols={cols}")

while (top <= bottom) and (left <= right):
    if direction == 0:
        for idx in range(left,right+1):             # moving left -> right
            enc_shcode.append(matrix[top][idx])            
        top += 1

    elif direction == 1:
        for idx in range(top,bottom+1):             # moving top -> bottom
            enc_shcode.append(matrix[idx][right])
        right -= 1
    
    elif direction == 2:
        for idx in range(right,left-1,-1):          # moving right -> left
            enc_shcode.append(matrix[bottom][idx])
        bottom -= 1
    
    elif direction == 3:
        for idx in range(bottom,top-1,-1):          # moving bottom -> top
            enc_shcode.append(matrix[idx][left])
        left += 1
    
    direction = (direction + 1) % 4

# print as C-array
print("{ ", end='')
print(",".join("0x{:02x}".format(c) for c in enc_shcode), end='')
print(" }")
print(f"Length: {len(enc_shcode)}")