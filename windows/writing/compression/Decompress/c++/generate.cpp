/*
    Generator 

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp  
*/

#include <windows.h>
#include <stdint.h>
#include <compressapi.h>
#include <stdio.h>

#pragma comment(lib,"cabinet")

int main()
{
    HANDLE  f;
    SIZE_T  payload_len, compressed_len;
    DWORD   nread;
    COMPRESSOR_HANDLE engine;

    uint8_t * payload;
    uint8_t * compressed;

    int idx = 1;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // create LZMS compressor
    CreateCompressor (COMPRESS_ALGORITHM_LZMS, NULL, &engine);
    
    // create buffer for compressed data
    Compress (engine, payload, payload_len, NULL, 0, &compressed_len);
    compressed = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, compressed_len);

    // CompressHEAP_ZERO_MEMORY
    Compress (engine, payload, payload_len, compressed, compressed_len, &compressed_len);

    // print
    printf ("{ 0x%02x", compressed[0]);
    for (idx = 1; idx < compressed_len; idx++)
    {
        printf (",0x%02x", compressed[idx]);
    }
    printf (" }\n");
    printf ("Payload Length: %lld\n", payload_len);
    printf ("Compressed Payload Length: %lld\n", compressed_len);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);
    HeapFree (GetProcessHeap(), 0, compressed);

    return 0;
}