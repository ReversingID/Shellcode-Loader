/*
    Generator
    Encryption with Tiny Encryption Algorithm (TEA).

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp

Note:
    encrypt with CBC mode.
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

void block_encrypt (uint32_t val[2], uint32_t key[4])
{
    uint32_t v0 = val[0], v1 = val[1];
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    uint32_t delta = 0x9E3779B9, sum = 0, i;

    // Round: 32
    for (i =  0; i < 32; i++)
    {
        // Round-Function
        sum += delta;
        v0  += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1  += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }

    val[0] = v0;
    val[1] = v1;
}

void encrypt (uint32_t * data, uint32_t block_count, uint32_t key[4], uint32_t iv[2])
{
    uint32_t i;
    uint32_t prev_block[2];

    prev_block[0] = iv[0];
    prev_block[1] = iv[1];

    for (i = 0; i < block_count; i += 2)
    {
        // XOR plaintext block with previous ciphertext block
        data[i    ] ^= prev_block[0];
        data[i + 1] ^= prev_block[1];

        // encrypt plaintext to ciphertext
        block_encrypt(&data[i], key);

        // store ciphertext block for next operation
        prev_block[0] = data[i    ];
        prev_block[1] = data[i + 1];
    }
}


int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t  *  payload;
    uint32_t    idx, nitem = 0;
    SIZE_T      remainder, multiple = 8;    // 2x 4-byte 

                    //    R E V E     R S I N     G . I D     1 3 3 7
    uint32_t key[4] = { 0x52455645, 0x5253494E, 0x472E4944, 0x31333337 };
    uint32_t iv[2]  = { 0x13510030, 0x13510030 };

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % multiple;
    if (remainder)
        payload_len += (multiple - remainder);
    nitem = 2 * payload_len / multiple;

    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encrypt data, 
    encrypt ((uint32_t*)payload, nitem, key, iv);

    // print
    printf("{");
    for (idx = 0; idx < payload_len; idx++)
    {
        if (idx % 16 == 0)
            printf("\n  ");
        
        printf("0x%02x, ", payload[idx]);
    }
    printf("\n}\n");
    printf ("Length: %lld\n", payload_len);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}