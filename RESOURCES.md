# Resources dan Indeks Teknik

Dokumen ini menyediakan indeks lengkap dari semua teknik loading shellcode yang didokumentasikan dalam repository ini, beserta referensi eksternal dan sumber daya terkait.

## Daftar Teknik Berdasarkan Platform

### Linux

#### Allocation (Alokasi Memory)
- **Dokumentasi:** [linux/allocation/README.md](linux/allocation/README.md)
- **Deskripsi:** Strategi alokasi memory untuk menampung shellcode sebagai kode executable
- **Fokus:** Teknik alokasi memory di sistem Linux

#### Storage (Penyimpanan)
- **Dokumentasi:** [linux/storage/README.md](linux/storage/README.md)
- **Deskripsi:** Teknik penyimpanan shellcode sebelum eksekusi
- **Fokus:** Berbagai lokasi penyimpanan shellcode (stack, heap, global data)

#### Execution (Eksekusi)
- **Dokumentasi:** [linux/execution/README.md](linux/execution/README.md)
- **Deskripsi:** Strategi eksekusi shellcode di Linux
- **Fokus:** Cara mengeksekusi kode dari memory

#### Writing (Penulisan Kode)
- **Dokumentasi:** [linux/writing/README.md](linux/writing/README.md)
- **Deskripsi:** Strategi menulis/memodifikasi kode di memory
- **Fokus:** Self-modifying code dan transformasi shellcode

#### Permission (Izin Akses)
- **Dokumentasi:** [linux/permission/README.md](linux/permission/README.md)
- **Deskripsi:** Manajemen permission memory untuk eksekusi
- **Fokus:** Mengubah attributes memory untuk eksekusi kode

---

### Windows

#### Access (Akses API Windows)
- **Dokumentasi:** [windows/access/README.md](windows/access/README.md)
- **Deskripsi:** API Windows yang digunakan dalam loading shellcode
- **Fokus:** Memory allocation, permission, dan API execution

#### Allocation (Alokasi Memory)
- **Dokumentasi:** [windows/allocation/README.md](windows/allocation/README.md)
- **Deskripsi:** Teknik alokasi memory di Windows
- **Fokus:** VirtualAlloc, VirtualAllocEx, GlobalAlloc dan variasi lainnya

#### Storage (Penyimpanan)
- **Dokumentasi:** [windows/storage/README.md](windows/storage/README.md)
- **Deskripsi:** Lokasi penyimpanan shellcode di Windows
- **Fokus:** Berbagai sumber shellcode dan metode penyimpanan

#### Execution (Eksekusi)
- **Dokumentasi:** [windows/execution/README.md](windows/execution/README.md)
- **Deskripsi:** Teknik eksekusi shellcode di Windows
- **Fokus:** Berbagai metode untuk mengeksekusi kode

##### Sub-Teknik Eksekusi Windows:
- **ASM Jump** - [windows/execution/asm-jmp/README.md](windows/execution/asm-jmp/README.md)
  - Menggunakan assembly language untuk jump ke shellcode
  
- **Callback** - [windows/execution/callback/README.md](windows/execution/callback/README.md)
  - Eksekusi melalui callback functions
  
- **Event** - [windows/execution/event/README.md](windows/execution/event/README.md)
  - Menggunakan event handling untuk eksekusi
  
- **Fiber** - [windows/execution/fiber/README.md](windows/execution/fiber/README.md)
  - Menggunakan Windows Fiber API
  
- **Invoke** - [windows/execution/invoke/README.md](windows/execution/invoke/README.md)
  - Direct invocation dari function pointer
  
- **Thread** - [windows/execution/thread/README.md](windows/execution/thread/README.md)
  - Eksekusi menggunakan thread (CreateThread, CreateRemoteThread)

#### Writing (Penulisan Kode)
- **Dokumentasi:** [windows/writing/README.md](windows/writing/README.md)
- **Deskripsi:** Strategi penulisan shellcode ke memory
- **Fokus:** RtlMoveMemory, memcpy, dan metode copying lainnya

#### Permission (Izin Akses)
- **Dokumentasi:** [windows/permission/README.md](windows/permission/README.md)
- **Deskripsi:** Manajemen permission memory di Windows
- **Fokus:** VirtualProtect, VirtualProtectEx untuk mengubah page attributes

#### Concealment (Penyembunyian Runtime)
- **Dokumentasi:** [windows/concealment/README.md](windows/concealment/README.md)
- **Deskripsi:** Teknik mengurangi observabilitas implant selama dan setelah loading
- **Fokus:** Menyembunyikan artefak in-memory dari scanner, EDR, dan analisis forensik

##### Sub-Teknik Concealment Windows:
- **Module Stomping** - [windows/concealment/module-stomping/README.md](windows/concealment/module-stomping/README.md)
  - Menempatkan shellcode di dalam image modul legitim (code cave, section overwrite, dll.)

- **Sleep Obfuscation** - [windows/concealment/sleep-obfuscation/README.md](windows/concealment/sleep-obfuscation/README.md)
  - Mengenkripsi atau menyembunyikan memori implant selama periode idle (Ekko, Foliage, dll.)

- **Stack Spoofing** - [windows/concealment/stack-spoofing/README.md](windows/concealment/stack-spoofing/README.md)
  - Memalsukan rantai return address agar stack unwinding terlihat legitim

---

## Sumber Daya Eksternal

### Repository ReversingID Terkait

#### [ReversingID/shellcodes](https://github.com/ReversingID/shellcodes)
- **Deskripsi:** Koleksi shellcode yang siap digunakan
- **Isi:** Shellcode untuk berbagai platform dan aksi
- **Penggunaan:** Referensi untuk berbagai jenis shellcode yang dapat diload menggunakan teknik di repository ini

#### [ReversingID/injection](https://github.com/ReversingID/injection)
- **Deskripsi:** Teknik process injection dan payload delivery
- **Isi:** Berbagai metode injeksi shellcode ke process
- **Penggunaan:** Melengkapi shellcode loading dengan delivery methods yang lebih advanced

#### [ReversingID](https://github.com/ReversingID)
- **Deskripsi:** Organisasi ReversingID di GitHub
- **Isi:** Berbagai repository tentang reverse engineering dan keamanan

---

## Referensi Dokumentasi

### Windows API Documentation
- [Microsoft Windows API Reference](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list)
- Virtual Memory Functions: VirtualAlloc, VirtualAllocEx, VirtualProtect, VirtualProtectEx
- Threading Functions: CreateThread, CreateRemoteThread, CreateRemoteThreadEx
- Memory Functions: RtlMoveMemory, memcpy

### Linux System Calls
- [man7.org Linux manual pages](https://man7.org/)
- Memory Management: mmap, mprotect, munmap
- Process Management: fork, exec, ptrace

### Tools & References
- **IDA Pro / Ghidra:** Reverse engineering dan analysis
- **Debuggers:** WinDbg, gdb, x64dbg
- **Disassemblers:** Radare2, Capstone
- **Memory Editors:** Cheat Engine, HxD

---

## Daftar Cepat (Quick Reference)

| Topik | Linux | Windows |
|-------|-------|---------|
| **Allocation** | [allocation/](linux/allocation/) | [allocation/](windows/allocation/) |
| **Storage** | [storage/](linux/storage/) | [storage/](windows/storage/) |
| **Execution** | [execution/](linux/execution/) | [execution/](windows/execution/) |
| **Writing** | [writing/](linux/writing/) | [writing/](windows/writing/) |
| **Permission** | [permission/](linux/permission/) | [permission/](windows/permission/) |
| **Access** | - | [access/](windows/access/) |
| **Concealment** | - | [concealment/](windows/concealment/) |

---

## Cara Menggunakan Repository Ini

1. **Pemula:** Mulai dengan membaca [README.md](README.md) untuk overview
2. **Eksplorasi Teknik:** Pilih platform (Linux/Windows) dan teknik yang menarik
3. **Pelajari Implementasi:** Baca README di setiap direktori teknik dan study kode
4. **Eksperimen:** Compile dan modifikasi kode untuk pembelajaran lebih dalam
5. **Berkontribusi:** Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk menambahkan teknik baru

---

## Tips Navigasi

- **Untuk teknik spesifik:** Gunakan daftar di atas untuk langsung ke folder teknik
- **Untuk platform tertentu:** Mulai dengan README di [linux/](linux/) atau [windows/](windows/)
- **Untuk kontribusi:** Baca [CONTRIBUTING.md](CONTRIBUTING.md) dan [CONTRIBUTING.EN.md](CONTRIBUTING.EN.md)

---

Terakhir diupdate: 2026-06-09
