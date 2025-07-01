# Shellcode Loader

Transforming the shellcode with custom algorithm.

### Overview

Melakukan manipulasi bit berupa `inverse` untuk setiap bit pada byte shellcode.

Inverse adalah operasi mengganti bit dengan kebalikannya, yakni bit `1` menjadi `0` dan `0` menjadi `1`. Sebagai contoh, `0x90` dalam representasi binary adalah `1001 0000`. Operasi inverse akan menghasilkan nilai `0110 1111`.