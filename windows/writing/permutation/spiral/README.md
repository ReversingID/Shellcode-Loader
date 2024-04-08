# Shellcode Loader

Reordering the shellcode with custom algorithm.

### Overview

Mengatur posisi byte dalam shellcode dengan pola spiral.

contoh:

```
awal: 
     1  2  3  4
     5  6  7  8
     9 10 11 12
    13 14 15 16
hasil:
    1 2 3 4 8 12 16 15 14 13 9 5 6 7 11 10
```

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.

### Reference 
