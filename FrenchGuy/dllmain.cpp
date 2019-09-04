// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "FrenchGuy.h"
#include "../gamedefs.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)& FrenchGuyThread, 0, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		HWND windowHandle = FindWindowA(GAME_WINDOW_CLASS, GAME_WINDOW_NAME);
		unsigned long gamePid;
		GetWindowThreadProcessId(windowHandle, &gamePid);
		HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, gamePid);
		CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"), (LPVOID)420, 0, 0);
		CloseHandle(procHandle);
		ExitProcess(0);
        break;
    }
    return TRUE;
}

