# Shellcode Loader

Reordering the shellcode with custom algorithm.

### Overview

Mengatur posisi byte dalam shellcode dengan pola mengular.

contoh:

```
awal: 
    1  2  3  4
    5  6  7  8
    9 10 11 12
hasil:
    1 2 3 4 8 7 6 5 9 10 11 12
```

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.

### Reference 
