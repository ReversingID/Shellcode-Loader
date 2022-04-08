# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan konversi endianness (little-endian dan big-endian byte order).

Endian adalah urutan byte dari sebuah bilangan jika direpresentasikan di memory. Dalam representasi big-endian, penulisan byte diawali dari most-significant byte. Sementara little-endian diawali dari least-significant byte.

Konversi antara little-endian dan big-endian dapat dilakukan melalui fungsi `ntoh` dan `hton`, dimana fungsi ntoh (network to host) mengasumsikan bilangan dalam big-endian dan akan dikonversi menjadi little endian. Sementara hton sebaliknya.


```c++
uint32_t htonl (uint32_t hostlong);
uint64_t htonll (uint64_t hostlong);

uint32_t ntohl (uint32_t netlong);
uint64_t ntohll (uint64_t netlong);
```

### Reference

- [MSDN htonl](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htonl)
- [MSDN htonll](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htonll)
- [MSDN ntohl](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ntohl)
- [MSDN ntohll](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-ntohll)
