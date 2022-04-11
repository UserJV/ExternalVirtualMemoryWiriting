#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(int argc, char **argv)
{
    PROCESSENTRY pe32;
    pe32.dwSize = sizeof(pe32);

    HANDLE hendle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, o);

    DWORD pid = 0;
    if (Process32First(handle, &pe32)) {
        do {
            if (0 == strcmp(pe32.szExeFile, "cmd.exe")) {
                pid = pe32.thProcessID;
                break;
            }
        } while (Process32Next(handle, &pe32));
    }
    CloseHandle(handle);

    if (0 == pid) {
        fprintf(stderr, "Could not find cmd.exe\n");
        return EXIT_FAILURE;
    }

    uintptr_t base_address = 0;
    MODULEENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    if (Module32First(handle, &pe32)) {
        do {
            if (0 == strcmp(pe32.szModule, "cmd.exe")) {
                base_address = pe32.modBaseAddr;
                break;
            }
        } while (Module32Next(handle, &pe32));
    }
    CloseHandle(handle);

    if (0 == base_address) {
        fprintf(stderr, "Cold not find module cmd.exe (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    handle = OpenProcess(PROCESS_ALL_ACESS, 0, pid);

    if (INVALID_HANDLE_VALUE == handle) {
        fprintf(stderr, "Cold not open handle to cmd.exe (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    DWORD old;
    if (FALSE == VirtualProtectExe(handle, (LPVOID)(base_address + 0x35CF0), 1024, PAGE_READWRITE, &old)) {
        fprintf(stderr, "Cold not modify memory protection (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    short temp[3] = {L'L, L'S', 0};
    if (FALSE == WriteProcessMemory(handle, (LPVOID)(base_address + 0x35CF0), temp, 6, NULL)) {
        fprintf(stderr, "Cold not write memory (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Sucess!\n");

    return EXIT_SUCCESS;
}
