# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `UuidFromString`.

Fungsi ini akan mengubah UUID dari representasi string menjadi binary. Sebuah UUID adalah GUID dengan ukuran tetap 16 byte. Representasi UUID/GUID dalam binary merupakan little endian.

Karena UUID dapat dianggap sebagai sebuah blok berukuran 16 byte, maka sebuah shellcode yang besar harus dipecah menjadi beberapa UUID. Padding perlu dilakukan agar ukuran data terjaga sebagai kelipatan 16.

```c++
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;

RPC_STATUS UuidFromStringA (RPC_CSTR StringUuid, UUID *Uuid);

RPC_STATUS UuidFromStringW (RPC_WSTR StringUuid, UUID *Uuid);

RPC_STATUS UuidToStringA (const UUID *Uuid, RPC_CSTR *StringUuid);

RPC_STATUS UuidToStringW (const UUID *Uuid, RPC_WSTR *StringUuid);
```

### Reference

- [MSDN UuidFromStringA](https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)
- [MSDN UuidFromStringW](https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidtotringw)
- [MSDN UuidToStringA](https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)
- [MSDN UuidToStringW](https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidtostringw)
