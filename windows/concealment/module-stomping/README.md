# Shellcode Loader

Menempatkan shellcode di dalam image modul yang sudah dimuat.

### Overview

Teknik `module-stomping` menempatkan payload ke dalam ruang memori yang sudah terasosiasi dengan DLL (`MEM_IMAGE`), alih-alih menciptakan region private executable baru melalui `VirtualAlloc`. Tujuannya adalah mengurangi anomali memori seperti region RWX privat yang sering menjadi sinyal deteksi EDR.

### Related

- [module-enumeration](../../access/module-enumeration): resolusi dan penemuan modul yang dimuat.
- [permission](../../permission): perubahan atribut halaman memori (`VirtualProtect`, `NtProtectVirtualMemory`).
- [writing](../../writing): penyalinan shellcode ke region target.

