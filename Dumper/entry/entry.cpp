
#include "../main.h"
#include <windows.h>
#include <cstdio>
#include <iostream>

static FILE* pConsoleStdout = nullptr;
static FILE* pConsoleStderr = nullptr;
static bool consoleAllocated = false;

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hinstDLL);

        if (AllocConsole()) {
            consoleAllocated = true;
            if (freopen_s(&pConsoleStdout, "CONOUT$", "w", stdout) != 0) {
                FreeConsole();
                return FALSE;
            }
            if (freopen_s(&pConsoleStderr, "CONOUT$", "w", stderr) != 0) {
                if (pConsoleStdout) fclose(pConsoleStdout);
                FreeConsole();
                return FALSE;
            }
            std::cout.clear();
            std::cerr.clear();
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED) {
            }
            else {
                MessageBoxA(NULL, ("AllocConsole error: " + std::to_string(error)).c_str(), "Hook Error", MB_ICONERROR | MB_OK);
                return FALSE;
            }
        }

        HANDLE hThread = CreateThread(
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)main::thread,
            hinstDLL,
            0,
            nullptr
        );

        if (hThread) {
            CloseHandle(hThread);
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "!!! CRITICAL ERROR: Failed to create agent thread. GetLastError() = "
                << error << std::endl;

            if (consoleAllocated) {
                if (pConsoleStdout) { fclose(pConsoleStdout); pConsoleStdout = nullptr; }
                if (pConsoleStderr) { fclose(pConsoleStderr); pConsoleStderr = nullptr; }
                FreeConsole();
                consoleAllocated = false;
            }
            return FALSE;
        }
        break;
    }

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:

        if (consoleAllocated && lpvReserved == NULL) {
            if (!FreeConsole()) {
            }
            consoleAllocated = false;
        }
        else if (consoleAllocated && lpvReserved != NULL) {
        }
        break;
    }
    return TRUE;
}
