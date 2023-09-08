# Shellcode Loader

Transforming the shellcode by byte substitution.

### Overview

Menggunakan enkripsi klasik Affine Cipher untuk mengganti byte sesuai rumus `(ax + b) mod m` dengan a=197, b=37, m=256. Dekripsi menggunakan rumus `i(y - b) mod m` dengan i merupakan inverse dari a yakni i=13, b=37, dan m=256.