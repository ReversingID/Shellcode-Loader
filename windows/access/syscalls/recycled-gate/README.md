# Shellcode Loader

Access the Windows API via direct syscall by reusing an existing syscall instruction from ntdll (Recycled Gate).

### Overview

Recycled Gate menghindari alokasi halaman RWX baru untuk instruksi `syscall`. Sebaliknya, instruksi `syscall; ret` (`0F 05 C3`) yang sudah ada di dalam section `.text` ntdll.dll digunakan kembali sebagai gate. Karena instruksi `syscall` berasal dari ntdll yang sah, teknik ini lebih sulit dideteksi oleh solusi yang memantau eksekusi `syscall` dari halaman memori baru.

Trampoline statis (x64 only, Windows 10+):

1. `RecycledSetSyscallAddr(addr)` — menyimpan alamat `syscall; ret` yang ditemukan di ntdll ke variabel global `pRecycledSyscall` (`.data`)
2. `RecycledGate(ssn)` — menyimpan SSN ke variabel global `wSystemCall` (`.data`)
3. `RecycledDescent(...)` — stub di `.text` yang menyiapkan register lalu melompat ke ntdll:

```
mov r10, rcx
mov eax, wSystemCall
mov r11, pRecycledSyscall
jmp r11
```

### Compile

```sh
ml64.exe /nologo /c recycledgate.asm
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp recycledgate.obj
```

Memerlukan x64 Developer Command Prompt.

### Note

- Sample ini **x64 only** (layout stub ntdll Win10+, pola `4C 8B D1 B8`).
- Syscall dieksekusi lewat `RecycledGate` / `RecycledDescent` di image modul (bukan alokasi heap RWX per-SSN).
- Instruksi `syscall` sendiri di-recycle dari ntdll; stub register-setup berada di `.text` modul.

### Reference

- [Klezvirus — Recycled Gate](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)
