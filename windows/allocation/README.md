# Shellcode Loader

### Overview

Proses `allocation` digunakan untuk menciptakan ruang yang cukup untuk menampung shellcode yang telah diekstrak dari ruang penyimpanan (global/stack/resource/download). Memory yang telah dialokasikan haruslah ditandai sebagai executable. Hal ini dilakukan untuk menghindari adanya exception oleh DEP (Data Execution Prevention).