#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "xor.h"
#include "conio.h"

DWORD get_proc_id(const char* proc_name)
{
    DWORD proc_id = 0;
    auto* const h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (h_snap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 proc_entry;
        proc_entry.dwSize = sizeof(proc_entry);

        if (Process32First(h_snap, &proc_entry))
        {
            do
            {
                if (!_stricmp(proc_entry.szExeFile, proc_name))
                {
                    proc_id = proc_entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(h_snap, &proc_entry));
        }
    }

    CloseHandle(h_snap);
    return proc_id;
}

int main()
{
    char szPath[MAX_PATH];
    GetFullPathName(xorstr("darwin.dll"), MAX_PATH, szPath, NULL);
    const char* proc_name = xorstr("RustClient.exe");
    DWORD proc_id = 0;

    while (!proc_id)
    {
        proc_id = get_proc_id(proc_name);
        Sleep(30);
    }

    auto* const h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);

    if (h_proc && h_proc != INVALID_HANDLE_VALUE)
    {
        const LPVOID nt_open_file = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");//ggez
        if (nt_open_file)
        {
            char original_bytes[5];
            memcpy(original_bytes, nt_open_file, 5);
            WriteProcessMemory(h_proc, nt_open_file, original_bytes, 5, nullptr);
        }

        auto* loc = VirtualAllocEx(h_proc, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(h_proc, loc, szPath, strlen(szPath) + 1, nullptr);
        auto* const h_thread = CreateRemoteThread(h_proc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, nullptr);

        if (h_thread) CloseHandle(h_thread);
    }

    if (h_proc) CloseHandle(h_proc);

    std::cout << xorstr("[+] Darwin Injected Successfulled!") << std::endl;
    Sleep(3000);
    return 0;
}