// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	void* ldLibA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	VirtualProtect(ldLibA, 1, PAGE_EXECUTE_READWRITE, NULL);
	*((BYTE*)ldLibA) = 'a';
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBox(0, TEXT("Hey, I'm a dummy module. Should be unloading soon enough!"), TEXT("Dummy thing"), 0);
	case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}