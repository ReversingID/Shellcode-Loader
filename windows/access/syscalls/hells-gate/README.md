# Shellcode Loader

Access the Windows API via direct syscall (Hell's Gate).

### Overview

Hell's Gate membaca Syscall Service Number (SSN) langsung dari stub ntdll di memori dengan mencocokkan pola `4C 8B D1 B8` (`mov r10,rcx; mov eax,SSN`). 

Jika stub telah di-hook oleh EDR (byte awal diganti instruksi lain), SSN dibaca dari salinan ntdll.dll di disk yang belum dimodifikasi (fallback mechanism).

Trampoline statis (x64 only, Windows 10+):

1. `HellsGate(ssn)` — menyimpan SSN ke variabel global `wSystemCall` (`.data`)
2. `HellDescent(...)` — stub di `.text` yang mengeksekusi syscall:

```
mov r10, rcx
mov eax, wSystemCall
syscall
ret
```


### Compile

```sh
ml64.exe /nologo /c hellsgate.asm
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp hellsgate.obj
```

Memerlukan x64 Developer Command Prompt.

### Note

- Sample ini **x64 only** (layout stub ntdll Win10+).
- Fallback disk adalah ekstensi di atas implementasi asli, implementasi Hell's Gate tidak memuat mekanisme tersebut.

### Reference

- [am0nsec — HellsGate](https://github.com/am0nsec/HellsGate)
- [VX-Underground — Hell's Gate](https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf)
