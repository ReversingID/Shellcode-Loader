# Shellcode Loader

Penyalahgunaan sistem exception handling Windows untuk mengeksekusi shellcode.

### Overview

Teknik `exception` mendaftarkan shellcode sebagai handler exception atau memanfaatkan alur SEH (Structured Exception Handling). Eksekusi terpicu saat exception dilempar — baik secara sengaja (`RaiseException`) maupun sebagai respons terhadap fault — sehingga transfer kontrol ke shellcode terselubung di dalam rantai exception handling.

Variasi dikelompokkan berdasarkan lapisan handler: vectored handler, top-level filter, dan SEH inline.

### Catalog

**Vectored handler**

- [AddVectoredExceptionHandler](AddVectoredExceptionHandler): daftarkan shellcode sebagai vectored exception handler; picu dengan `RaiseException`.

**Top-level filter**

- [SetUnhandledExceptionFilter](SetUnhandledExceptionFilter): daftarkan shellcode sebagai filter exception tingkat atas untuk exception yang tidak tertangani.

**SEH inline**

- [seh-catch-exception](seh-catch-exception): eksekusi shellcode di dalam blok `__except` setelah exception tertangkap secara lokal.
