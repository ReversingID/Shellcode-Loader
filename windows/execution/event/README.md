# Shellcode Loader

### Overview

Eksekusi shellcode berdasarkan event tertentu.

Teknik `event` menunda atau memicu eksekusi shellcode melalui mekanisme penjadwalan Windows: APC (Asynchronous Procedure Call), timer, thread pool, atau wait pada handle sinkronisasi. Shellcode dijalankan sebagai callback/routine yang terpicu saat kondisi event terpenuhi — bukan melalui pemanggilan langsung dari alur utama program.

Variasi dikelompokkan berdasarkan primitif pemicu: antrian APC, timer, thread pool, dan wait handle.

### Catalog

**APC (Asynchronous Procedure Call)**

- [QueueUserAPC](QueueUserAPC): antrikan shellcode sebagai user APC pada thread target; picu dengan `NtTestAlert` atau state alertable.
- [NtQueueApcThread](NtQueueApcThread): varian native `NtQueueApcThread` untuk mengantri APC ke thread.
- [NtQueueApcThreadEx](NtQueueApcThreadEx): varian extended native APC dengan opsi `USER_APC_OPTION`.

**Timer**

- [SetTimer](SetTimer): timer berbasis HWND; callback `TIMERPROC` saat interval habis.
- [CreateTimerQueueTimer](CreateTimerQueueTimer): timer queue legacy; callback `WAITORTIMERCALLBACK` pada antrian timer.
- [SetWaitableTimer](SetWaitableTimer): waitable timer dengan completion routine APC; thread harus alertable (`SleepEx`).
- [timeSetEvent](timeSetEvent): multimedia timer (obsolete); callback periodik via `winmm.dll`.

**Thread pool**

- [CreateThreadpoolTimer](CreateThreadpoolTimer): timer thread pool Vista+; callback `PTP_TIMER_CALLBACK` pada worker pool.
- [CreateThreadpoolWait](CreateThreadpoolWait): wait thread pool; callback saat handle sinkronisasi ter-signal.

**Wait handle**

- [RegisterWaitForSingleObject](RegisterWaitForSingleObject): daftarkan callback yang berjalan saat object (event, process, dll.) ter-signal.

### Related

- [execution/callback](../callback): eksekusi implisit melalui callback API lain.
- [execution/thread](../thread): eksekusi shellcode sebagai thread baru, bukan callback event.
