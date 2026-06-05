; Tartarus' Gate — static syscall trampoline (x64)
; SSN in .data; TartarusDescent in .text (no heap allocation)

.data
    wSystemCall DWORD 0

.code
TartarusGate PROC
    mov wSystemCall, ecx
    ret
TartarusGate ENDP

TartarusDescent PROC
    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret
TartarusDescent ENDP
END
