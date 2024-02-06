# Shellcode Loader

Reordering the shellcode with custom algorithm.

### Overview

Mengatur posisi byte dalam shellcode menggunakan algoritma rail-fence (zig-zag) cipher. 

Shellcode yang tersimpan memiliki format `[Key] [Encoded Shellcode]`.

### Reference 

- [Wiki Rail-Fence Cipher](https://en.wikipedia.org/wiki/Rail_fence_cipher)
- [online encoder/decoder](https://www.dcode.fr/rail-fence-cipher)