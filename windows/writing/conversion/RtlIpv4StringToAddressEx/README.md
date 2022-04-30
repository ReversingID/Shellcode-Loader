# Shellcode Loader

Writing shellcode to allocated memory.

### Overview

Penyalinan shellcode menggunakan `RtlIpv4StringToAddressEx`.

Fungsi ini akan mengubah IPv4 address dan port dari representasi string menjadi binary. IPv4 address adalah identitas host yang berperan dalam pengalamatan logis di jaringan. Sementara port adalah identitas service yang dibuka dalam suatu host. Ukuran sebuah IPv4 address adalah 4 byte dan port adalah 2 byte.

Dengan demikian, notasi IPv4:port dapat dianggap sebagai sebuah blok berukuran 6 byte. Sehingga shellcode yang besar dipecah menjadi beberapa blok. Padding perlu dilakukan agar ukuran data terjaga sebagai kelipatan 6.

```c++
NTSTATUS RtlIpv4StringToAddressExA (PCSTR AddressString, BOOLEAN Strict, in_addr *Address, PUSHORT Port);

NTSTATUS RtlIpv4StringToAddressExW (PCWSTR AddressString, BOOLEAN Strict, in_addr *Address, PUSHORT Port);

NTSTATUS RtlIpv4AddressToStringExA (const in_addr *Address, USHORT Port, PSTR AddressString, PULONG AddressStringLength);

NTSTATUS RtlIpv4AddressToStringExW (const in_addr *Address, USHORT Port, PWSTR AddressString, PULONG AddressStringLength);
```

### Reference

- [MSDN RtlIpv4StringToAddressExA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressexa)
- [MSDN RtlIpv4StringToAddressExW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressexw)
- [MSDN RtlIpv4AddressToStringExA](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringexa)
- [MSDN RtlIpv4AddressToStringExW](https://docs.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringexw)
- [MSDN in_addr structure](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-in_addr)