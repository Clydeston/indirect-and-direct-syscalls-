.code

; Direct syscall example: NtAllocateVirtualMemory
NtAllocateVirtualMemory_Direct proc
    mov r10, rcx
    mov eax, 18h          ; SSN
    syscall
    ret
NtAllocateVirtualMemory_Direct endp

; Indirect syscall example: NtCreateThreadEx
extern g_SyscallGadget:QWORD
extern g_SSN_NtCreateThreadEx:DWORD

NtCreateThreadEx_Indirect proc
    mov r10, rcx
    mov eax, g_SSN_NtCreateThreadEx
    
    ; allocate shadow space & align stack
    ; without this was causing crashes 
    sub rsp, 28h
    
    ; call the gadget (not jmp!) so we can clean up the stack afterward
    call qword ptr [g_SyscallGadget]
    
    ; clean up shadow space
    add rsp, 28h
    ret
NtCreateThreadEx_Indirect endp

end
