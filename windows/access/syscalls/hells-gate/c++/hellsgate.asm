; Hell's Gate — static syscall trampoline (x64)
; SSN in .data; HellDescent in .text (no heap allocation)

.data
    wSystemCall DWORD 0

.code
HellsGate PROC
    mov wSystemCall, ecx
    ret
HellsGate ENDP

HellDescent PROC
    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret
HellDescent ENDP
END
