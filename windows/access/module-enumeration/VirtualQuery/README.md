# Shellcode Loader

Access the Windows API by module enumeration.

### Overview

Resolve base address sebuah module (misal `kernel32.dll`) dengan memindai address space proses menggunakan `VirtualQuery`. Alamat fungsi dapat diperoleh melalui manual export walk by name. Pendekatan ini tidak menelusuri `PEB.Ldr`, tidak memanggil `GetModuleHandle`, `GetProcAddress`, atau `LoadLibrary`.

Teknik ini memfokuskan pada langkah resolusi modul:
- iterasi setiap region memori dengan `VirtualQuery`
- filter region bertipe `MEM_IMAGE` dan status `MEM_COMMIT`
- validasi header PE pada `AllocationBase`
- mencocokkan `IMAGE_EXPORT_DIRECTORY.Name` dengan nama DLL target.

`VirtualQuery` dipanggil langsung (linker import) dalam sample ini. Pada shellcode nyata, `VirtualQuery` harus di-resolve secara terpisah (misalnya melalui PEB bootstrap, parse IAT, atau syscall `NtQueryVirtualMemory`).

### How It Works

1. Mulai dari alamat `NULL`; panggil `VirtualQuery` untuk mendapatkan `MEMORY_BASIC_INFORMATION` setiap region.
2. Filter region dengan `State == MEM_COMMIT` dan `Type == MEM_IMAGE` (halaman yang merupakan image PE yang dimuat).
3. Gunakan `AllocationBase` sebagai kandidat base address modul; validasi signature `MZ` dan `PE`.
4. Baca nama modul dari field `Name` pada export directory (`IMAGE_EXPORT_DIRECTORY`).
5. Bandingkan nama tersebut dengan DLL target (misal `kernel32.dll`) secara case-insensitive.
6. Jika cocok, kembalikan `AllocationBase` sebagai `DllBase`.
7. Parse export table dari `DllBase` dan cocokkan nama fungsi (lihat [`manual-name`](../../dynamic-load/manual-name)).

### Advantages

- Tetap berfungsi ketika linked list modul di PEB di-unlink atau dimanipulasi.
- Tidak membaca `PEB.Ldr` atau menelusuri `LDR_DATA_TABLE_ENTRY`.
- Menghindari hook EDR pada `GetModuleHandle` dan API loader Win32 lainnya.

### Disadvantages

- Pemindaian seluruh address space lebih lambat dibanding penelusuran linked list PEB.
- `VirtualQuery` dipanggil langsung dalam sample ini; shellcode nyata memerlukan bootstrap terpisah untuk mendapatkan pointer fungsi.
- Identitas modul bergantung pada `IMAGE_EXPORT_DIRECTORY.Name`, yang dapat berbeda dari `BaseDllName` pada kasus tertentu.
- `VirtualQuery` sendiri dapat dimonitor atau di-hook oleh produk keamanan.
- Hanya menangani modul yang sudah dimuat; tidak memuat DLL baru.

### Reference

- [VirtualQuery](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery)
- [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information)
- [IMAGE_EXPORT_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_export_directory)
- [manual-name](../../dynamic-load/manual-name): manual PE export walk by name
- [InLoadOrder](../InLoadOrder): variasi penelusuran modul melalui PEB `InLoadOrderModuleList`
