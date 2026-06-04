# Shellcode Loader

Access the Windows API via direct syscall with neighbor-based SSN inference (Halo's Gate).

### Overview

Halo's Gate memperluas Hell's Gate untuk menangani kasus di mana stub target telah di-hook. Strategi Halo's Gate sederhana, SSN dihitung dari stub fungsi NT yang bertetangga dan masih bersih.

Prinsipnya: SSN ditetapkan secara sekuensial sesuai urutan alamat stub Nt* di ntdll. Jika fungsi pada posisi `i` di-hook, dan fungsi pada posisi `i+k` memiliki SSN `N`, maka SSN target adalah `N - k`.

```
sorted Nt* stubs by address:
  [i-2]  NtAdjustPrivileges      SSN = X-2   (clean)
  [i-1]  NtAlertResumeThread     SSN = X-1   (clean)
  [i]    NtAllocateVirtualMemory SSN = X     (HOOKED)
  [i+1]  NtAlpcAcceptConnectPort SSN = X+1   (clean) → infer X = (X+1) - 1
```

Trampoline statis (x64 only, Windows 10+):

1. `HalosGate(ssn)` — menyimpan SSN ke variabel global `wSystemCall` (`.data`)
2. `HaloDescent(...)` — stub di `.text` yang mengeksekusi syscall:

```
mov r10, rcx
mov eax, wSystemCall
syscall
ret
```

### Compile

```sh
ml64.exe /nologo /c halosgate.asm
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp halosgate.obj
```

Memerlukan x64 Developer Command Prompt.

### Note

- Sample ini **x64 only** (layout stub ntdll Win10+, pola `4C 8B D1 B8`).
- Syscall dieksekusi lewat `HalosGate` / `HaloDescent` di image modul (bukan alokasi heap RWX per-SSN).

### Reference

- [smelly__vx — Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md)
