# Shellcode Loader

Access the Windows API via direct syscall with multi-offset hook detection (Tartarus' Gate).

### Overview

Tartarus' Gate memperluas Halo's Gate dengan mendeteksi dua posisi hook yang berbeda pada stub ntdll:

| Kondisi stub | Penjelasan |
|---|---|
| `4C 8B D1 B8 XX XX ...` | Bersih — SSN dibaca langsung |
| `E9 XX XX XX XX ...` | Hook di byte 0 — seluruh stub diganti JMP |
| `4C 8B D1 E9 XX XX ...` | Hook di byte 3 — `mov r10,rcx` utuh, `mov eax,SSN` diganti JMP |

Kedua kasus hook menggunakan neighbor scan yang sama dengan Halo's Gate untuk menginferensi SSN dari fungsi tetangga yang bersih.

Trampoline statis (x64 only, Windows 10+):

1. `TartarusGate(ssn)` — menyimpan SSN ke variabel global `wSystemCall` (`.data`)
2. `TartarusDescent(...)` — stub di `.text` yang mengeksekusi syscall:

```
mov r10, rcx
mov eax, wSystemCall
syscall
ret
```

### Compile

```sh
ml64.exe /nologo /c tartarusgate.asm
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp tartarusgate.obj
```

Memerlukan x64 Developer Command Prompt.

### Note

- Sample ini **x64 only** (layout stub ntdll Win10+, pola `4C 8B D1 B8`).
- Syscall dieksekusi lewat `TartarusGate` / `TartarusDescent` di image modul (bukan alokasi heap RWX per-SSN).

### Reference

- [trickster0 — Tartarus' Gate](https://github.com/trickster0/TartarusGate)
