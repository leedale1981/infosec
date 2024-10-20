#include <stdio.h>
#include <windows.h>
#include "detours.h"

static VOID (WINAPI * TrueSleep)(DWORD dwMilliseconds) = Sleep;

VOID WINAPI TimedSleep(DWORD dwMilliseconds)
{
    printf("Detoured! Sleeping for %d milliseconds\n", dwMilliseconds);
    TrueSleep(dwMilliseconds);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueSleep, TimedSleep);
        DetourTransactionCommit();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueSleep, TimedSleep);
        DetourTransactionCommit();
    }
    return TRUE;
}