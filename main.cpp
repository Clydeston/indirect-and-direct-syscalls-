#include <Windows.h>
#include <cstdio>
#include <cstdint>

typedef unsigned __int64 QWORD;

// definitions needed for asm - 
// gadget for an indirect syscall + ret 
// then the SSN number for create thread - syscall expects this value in eax
extern "C" {
    QWORD g_SyscallGadget = 0;
    DWORD g_SSN_NtCreateThreadEx = 0;
}

extern "C" NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern "C" NTSTATUS NtCreateThreadEx_Indirect(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// finding gadget needed for returning of func to ntdll
QWORD FindSyscallGadget() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll) return 0;
    PBYTE pFunc = (PBYTE)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pFunc) return 0;

    for (int i = 0; i < 64; i++) {
        // check if the first byte is 0x0F (syscall) OR 0xCC (int3 from debugger)      
        if ((pFunc[i] == 0x0F || pFunc[i] == 0xCC) &&
            pFunc[i + 1] == 0x05 &&
            pFunc[i + 2] == 0xC3)
        {
            return (QWORD)(pFunc + i);
        }
    }
    return 0;
}

int main() {
    DWORD dwTargetProcID = GetCurrentProcessId();
    HANDLE hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetProcID);
    if (!hTargetProc) { printf("OpenProcess failed: %d\n", GetLastError()); return 1; }

    PVOID pBuffer = NULL;
    SIZE_T regionSize = 0x1000;
    NTSTATUS status = NtAllocateVirtualMemory_Direct(
        hTargetProc,
        &pBuffer,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    printf("[Direct] NtAllocateVirtualMemory status: 0x%X, buffer: 0x%p\n", status, pBuffer);
    if (status != 0) return 1;

    BYTE payload[] = { 0xEB };
    WriteProcessMemory(hTargetProc, pBuffer, payload, sizeof(payload), NULL);

    g_SSN_NtCreateThreadEx = 0xC2; // Windows 10 22H2 check system ver
    g_SyscallGadget = FindSyscallGadget();
    if (!g_SyscallGadget) { printf("Gadget not found\n"); return 1; }
    printf("[Indirect] Gadget at: 0x%llX, SSN: 0x%X\n", g_SyscallGadget, g_SSN_NtCreateThreadEx);

    HANDLE hThread = NULL;
    status = NtCreateThreadEx_Indirect(
        &hThread,
        THREAD_ALL_ACCESS,  
        NULL,
        hTargetProc,
        pBuffer,
        NULL,
        FALSE,
        0, 0, 0,
        NULL
    );
    printf("[Indirect] NtCreateThreadEx status: 0x%X\n", status);

    return 0;
}
