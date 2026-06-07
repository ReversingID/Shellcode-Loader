# Shellcode Loader

Access the Windows API by PEB walk.

### Overview

Resolve base address `kernel32.dll` dengan menelusuri `InMemoryOrderModuleList` pada `PEB.Ldr`, lalu mendapatkan alamat fungsi melalui manual export walk by name. Tidak memanggil `GetModuleHandle`, `GetProcAddress`, atau `LoadLibrary`.

Teknik ini memfokuskan pada langkah resolusi modul:
- membaca PEB dari segment register
- iterasi linked list `InMemoryOrderModuleList`
- mencocokkan `BaseDllName` dengan nama DLL target. 

### How It Works

1. Baca `PEB.Ldr` dari segment register (`GS` pada x64, `FS` pada x86).
2. Ambil head dari `InMemoryOrderModuleList`.
3. Iterasi setiap entri; gunakan `CONTAINING_RECORD(entry, MY_LDR_ENTRY, InMemoryOrderLinks)` untuk mendapatkan struktur modul.
4. Bandingkan `BaseDllName` dengan nama DLL target (misal `kernel32.dll`).
5. Jika cocok, kembalikan `DllBase`.
6. Parse export table dari `DllBase` dan cocokkan nama fungsi (lihat [`manual-name`](../../dynamic-load/manual-name)).

### Advantages

- Menghindari hook EDR pada `GetModuleHandle` dan API loader Win32 lainnya.
- `InMemoryOrderModuleList` adalah list PEB yang paling umum digunakan dalam shellcode dan teknik evasi.
- `BaseDllName` tersedia langsung pada offset `InMemoryOrderLinks` di `LDR_DATA_TABLE_ENTRY`.

### Disadvantages

- String nama DLL tetap ada di binary, sehingga mudah ditemukan melalui analisis statis.
- Urutan modul pada list ini berbeda dari urutan pemuatan; entri pertama adalah executable utama, bukan `ntdll.dll` (berbeda dengan teknik syscall yang mengambil entri kedua untuk `ntdll.dll`).
- Hanya menangani modul yang sudah dimuat; tidak memuat DLL baru.

### Reference

- [PEB Structure](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
- [PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- [LDR_DATA_TABLE_ENTRY](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-ldr_data_table_entry)
- [manual-name](../../dynamic-load/manual-name): manual PE export walk by name
