# Shellcode Loader

Transform the shellcode with custom algorithm.

### Overview

Menyisipkan satu-byte sebagai padding block shellcode. Padding digunakan untuk menandai ukuran block atau banyaknya potongan shellcode di dalam block.

Shellcode yang tersimpan memiliki format `[M] [M-byte Shellcode] [N] [N-byte Shellcode] ... [Z] [Z-byte Shellcode]`.