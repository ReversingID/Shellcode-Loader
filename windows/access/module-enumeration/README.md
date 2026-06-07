# Shellcode Loader

Resolve module from PEB or memory scan.

### Overview

Teknik `module-enumeration` mendemonstrasikan cara mendapatkan `DllBase` modul target tanpa memanggil `GetModuleHandle`, `LoadLibrary`, atau API loader internal lainnya. Setelah `DllBase` diketahui, resolusi fungsi dapat dilanjutkan dengan teknik lain (misalnya export walk di [`dynamic-load/manual-name`](../dynamic-load/manual-name)).

Dua kelompok pendekatan yang diimplementasikan:

**PEB linked-list walk** — Windows menyimpan daftar modul yang telah dimuat di `PEB.Ldr` (`PEB_LDR_DATA`). Setiap entri modul (`LDR_DATA_TABLE_ENTRY`) terhubung ke tiga linked list berbeda:

- `InLoadOrderModuleList` — urutan saat modul dimuat ke memori.
- `InMemoryOrderModuleList` — urutan alokasi memori modul.
- `InInitializationOrderModuleList` — urutan inisialisasi DllMain modul.

Untuk mendapatkan entri modul dari pointer `LIST_ENTRY`, gunakan makro `CONTAINING_RECORD` dengan field link yang sesuai (`InLoadOrderLinks`, `InMemoryOrderLinks`, atau `InInitializationOrderLinks`).

**Memory scan** — memindai address space proses untuk menemukan region bertipe `MEM_IMAGE`, memvalidasi header PE, dan mencocokkan nama modul dari export directory. Pendekatan ini tidak bergantung pada `PEB.Ldr`.

### Catalog

Daftar teknik `module-enumeration` yang diimplementasikan:

**PEB linked-list walk**

- [InLoadOrder](InLoadOrder): resolusi modul dengan menelusuri `InLoadOrderModuleList` dan mencocokkan `BaseDllName`.
- [InMemoryOrder](InMemoryOrder): resolusi modul dengan menelusuri `InMemoryOrderModuleList` dan mencocokkan `BaseDllName`.
- [InInitializationOrder](InInitializationOrder): resolusi modul dengan menelusuri `InInitializationOrderModuleList` dan mencocokkan `BaseDllName`.

**Memory scan**

- [VirtualQuery](VirtualQuery): resolusi modul dengan memindai address space menggunakan `VirtualQuery` dan mencocokkan export name PE.

### Reference

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- [LDR_DATA_TABLE_ENTRY](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-ldr_data_table_entry)
- [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
- [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information)
