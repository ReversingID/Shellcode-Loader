# Shellcode Loader

Resolve module from PEB.

### Overview

Windows menyimpan daftar modul yang telah dimuat di `PEB.Ldr` (`PEB_LDR_DATA`). Setiap entri modul (`LDR_DATA_TABLE_ENTRY`) terhubung ke tiga linked list berbeda, masing-masing merepresentasikan urutan modul dari sudut pandang yang berbeda:

- `InLoadOrderModuleList` — urutan saat modul dimuat ke memori.
- `InMemoryOrderModuleList` — urutan alokasi memori modul.
- `InInitializationOrderModuleList` — urutan inisialisasi DllMain modul.

Teknik `peb-walk` mendemonstrasikan cara menelusuri salah satu list tersebut untuk mendapatkan `DllBase` modul target tanpa memanggil `GetModuleHandle`, `LoadLibrary`, atau API loader internal lainnya. Setelah `DllBase` diketahui, resolusi fungsi dapat dilanjutkan dengan teknik lain (misalnya export walk di [`dynamic-load/manual-name`](../dynamic-load/manual-name)).

Untuk mendapatkan entri modul dari pointer `LIST_ENTRY`, gunakan makro `CONTAINING_RECORD` dengan field link yang sesuai (`InLoadOrderLinks`, `InMemoryOrderLinks`, atau `InInitializationOrderLinks`).

### Catalog

Daftar teknik `peb-walk` yang diimplementasikan:

- [InLoadOrder](InLoadOrder): resolusi modul dengan menelusuri `InLoadOrderModuleList` dan mencocokkan `BaseDllName`.
- [InMemoryOrder](InMemoryOrder): resolusi modul dengan menelusuri `InMemoryOrderModuleList` dan mencocokkan `BaseDllName`.
- [InInitializationOrder](InInitializationOrder): resolusi modul dengan menelusuri `InInitializationOrderModuleList` dan mencocokkan `BaseDllName`.

### Reference

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- [LDR_DATA_TABLE_ENTRY](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-ldr_data_table_entry)
