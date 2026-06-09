# Shellcode Loader

### Overview

Eksekusi shellcode sebagai fiber.

Fiber merupakan unit eksekusi bersifat cooperative-multitasking. Serupa dengan thread, fiber berbagi ruang memory dengan thread/fiber lain dalam satu process.

Secara garis besar, shellcode yang telah diekstrak akan disalin ke ruang memory yang telah dialokasikan. Alamat shellcode kemudian menjadi fungsi entrypoint bagi fiber.

Variasi dikelompokkan berdasarkan cara fiber dibuat atau dipicu: API pembuatan fiber Win32, callback FLS, dan entry internal loader.

### Catalog

**Pembuatan fiber (Win32)**

- [CreateFiber](CreateFiber): buat fiber baru dengan `CreateFiber`; alamat shellcode sebagai `LPFIBER_START_ROUTINE`.
- [CreateFiberEx](CreateFiberEx): varian extended dengan kontrol commit/reserve stack terpisah.

**Callback FLS**

- [FlsAlloc](FlsAlloc): alokasikan indeks FLS (Fiber Local Storage); shellcode sebagai `PFLS_CALLBACK_FUNCTION` yang dipanggil saat fiber dihancurkan.

**Internal loader**

- [RtlUserFiberStart](RtlUserFiberStart): entry point internal ntdll untuk memulai eksekusi fiber via manipulasi TEB/TIB (undocumented).

### Related

- [execution/thread](../thread): eksekusi preemptive via thread, bukan cooperative fiber.
