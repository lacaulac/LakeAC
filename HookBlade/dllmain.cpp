// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "HookBlade.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HookBladeThread, 0, 0, 0);
		MessageBoxA(0, "HookBlade is here!", "LakeAC", 0);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		ExitProcess(0);
		break;
    }
    return TRUE;
}

