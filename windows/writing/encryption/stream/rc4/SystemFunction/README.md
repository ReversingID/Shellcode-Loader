# Shellcode Loader

Shellcode encryption

### Overview

Enkripsi RC4 menggunakan fungsi `SystemFunction032` atau `SystemFunction033` yang merupakan API internal (tak terdokumentasi).

Fungsi `SystemFunction032` digunakan untuk melakukan enkripsi dan `SystemFunction033` digunakan untuk dekripsi. Namun secara internal, keduanya menunjuk pada offset sama sehingga kedua fungsi dapat digunakan untuk melakukan enkripsi dan dekripsi menggunakan key yang sama.

```c++
NTSTATUS SystemFunction032 (struct ustring* data, struct ustring* key);

NTSTATUS SystemFunction033 (struct ustring* data, struct ustring* key);

typedef struct
{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} ustring;
```

### Reference

- [WineAPI SystemFunction032](https://source.winehq.org/WineAPI/SystemFunction032.html)
- [ReactOS SystemFunction032](https://doxygen.reactos.org/df/d13/sysfunc_8c.html#a66d55017b8625d505bd6c5707bdb9725)