# Shellcode Loader

### Overview

Eksekusi shellcode sebagai fiber.

Fiber merupakan unit eksekusi bersifat cooperative-multitasking. Serupa dengan thread, fiber berbagi ruang memory dengan thread/fiber lain dalam satu process.

Secara garis besar, shellcode yang telah diekstrak akan disalin ke ruang memory yang telah dialokasikan. Alamat shellcode kemudian menjadi fungsi entrypoint bagi fiber.