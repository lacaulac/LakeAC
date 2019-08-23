#include "pch.h"
#include "HookBlade.h"
#include "ModUtils.h"
#include <intrin.h>

typedef HMODULE(__stdcall* oLoadLibraryW)(LPCWSTR); //The mandatory typedef of the original function, so that we don't have to rely on inline assembly to call the original function
typedef HMODULE(__stdcall* oLoadLibraryA)(LPCSTR);
typedef void(__stdcall* oFreeLibraryAndExitThread)(HMODULE, DWORD);
typedef BOOL(__stdcall* oFreeLibrary)(HMODULE);
typedef LPVOID(__stdcall* oVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(__stdcall* oAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);

HMODULE __stdcall hkFnLoadLibraryW(LPCWSTR name); //The signature of our hook
HMODULE __stdcall hkFnLoadLibraryA(LPCSTR name);
void __stdcall hkFnFreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode);
BOOL __stdcall hkFnFreeLibrary(HMODULE hLibModule);
LPVOID hkFnVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
PVOID hkFnAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);

Hook* hkLoadLibraryW; //The hook object pointer, will be linked further down
Hook* hkLoadLibraryA;
Hook* hkFreeLibraryAndExitThread;
Hook* hkFreeLibrary;
Hook* hkVirtualAlloc;
Hook* hkAddVectoredExceptionHandler;

oLoadLibraryW origLoadLibraryW; //A pointer to the original LoadLibraryW address. Using the oLoadLibraryW typedef from line 15
oLoadLibraryA origLoadLibraryA;
oFreeLibraryAndExitThread origFreeLibraryAndExitThread;
oFreeLibrary origFreeLibrary;
oVirtualAlloc origVirtualAlloc;
oAddVectoredExceptionHandler origAddVectoredExceptionHandler;

HMODULE hbModule; //A handle to our module

std::vector<Hook*>* hooks;

DWORD __stdcall HookCheckThread(LPVOID parameter);

void HookBladeThread(LPVOID parameter)
{
#if NDEBUG
	if (IsDebuggerPresent())
	{
		ExitProcess(420);
	}
#endif // DEBUG
	hbModule = GetModuleHandleA("HookBlade.dll");

	hooks = new std::vector<Hook*>();

	//Linking the original function addresses to the function pointers (declarations around line 40)
	origLoadLibraryW = (oLoadLibraryW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	origLoadLibraryA = (oLoadLibraryA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	origFreeLibraryAndExitThread = (oFreeLibraryAndExitThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibraryAndExitThread");
	origFreeLibrary = (oFreeLibrary)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
	origVirtualAlloc = (oVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	origAddVectoredExceptionHandler = (oAddVectoredExceptionHandler)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");

	//Creation of the hook objects
	hkLoadLibraryW = new Hook((FARPROC)origLoadLibraryW, (FARPROC)& hkFnLoadLibraryW);
	hkLoadLibraryA = new Hook((FARPROC)origLoadLibraryA, (FARPROC)& hkFnLoadLibraryA);
	hkFreeLibraryAndExitThread = new Hook((FARPROC)origFreeLibraryAndExitThread, (FARPROC)& hkFnFreeLibraryAndExitThread);
	hkFreeLibrary = new Hook((FARPROC)origFreeLibrary, (FARPROC)& hkFnFreeLibrary);
	hkVirtualAlloc = new Hook((FARPROC)origVirtualAlloc, (FARPROC)& hkFnVirtualAlloc);
	hkAddVectoredExceptionHandler = new Hook((FARPROC)origAddVectoredExceptionHandler, (FARPROC)& hkFnAddVectoredExceptionHandler);

	//Adding the hooks created previously into a vector<Hook*>
	hooks->push_back(hkLoadLibraryA);
	hooks->push_back(hkLoadLibraryW);
	hooks->push_back(hkFreeLibraryAndExitThread);
	hooks->push_back(hkFreeLibrary);
	hooks->push_back(hkVirtualAlloc);
	hooks->push_back(hkAddVectoredExceptionHandler);

	bool areHooksInitialised = true;
	for (Hook* hk : *hooks)
	{
		areHooksInitialised = areHooksInitialised & hk->enable();
	}

	if (!areHooksInitialised)
		ExitProcess(-1);

	CreateThread(0, 0, &HookCheckThread, hooks, 0, 0);
}

DWORD __stdcall HookCheckThread(LPVOID parameter)
{

	//MessageBoxA(0, "Started checking for modified hooks :)", "LakeAC Alpha Info", MB_ICONASTERISK); //Debug message
	std::vector<Hook*>* hooks = (std::vector<Hook*>*)parameter; //Getting the vector<Hook*> containing all the (non-)active hooks
	while (true)
	{
#if NDEBUG
		if (IsDebuggerPresent())
		{
			ExitProcess(420);
		}
#endif // DEBUG
		for (Hook* hk : *hooks) //For each hook
		{
			if (!hk->isCurrentCodeOk()) //If the code placed at the address of the original function doesn't correspond to the state of the hook (active/inactive)
			{
				//Then we've detected something trying to undermine our hooking efforts, most likely a cheat.
				MessageBoxA(0, "An unwanted hook was detected. Exitting...", "LakeAC Alpha DETECTION", MB_ICONSTOP); //Debug message
				ExitProcess(420);
			}
		}
		Sleep(100);
	}
	return 0;
}

HMODULE hkFnLoadLibraryW(LPCWSTR name)
{
	bool isAllowed = (wcsstr(name, L"DummyDLL.dll") != NULL);
	//TODO: Do an md5 checksum on allowed files instead

	HMODULE tmp;
	if (isAllowed)
	{
		//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
		hkLoadLibraryW->disable();
		tmp = origLoadLibraryW(name);
		hkLoadLibraryW->enable();
		return tmp;
	}
	return GetModuleHandle(L"kernel32.dll"); //Returning an handle to the kernel32 module, in order to mess with the injector
} //NB: This hook allows partial block of module injections

HMODULE __stdcall hkFnLoadLibraryA(LPCSTR name)
{
	bool isAllowed = (strcmp(name, "DummyDLL.dll") != NULL) | ModUtils::isInsideModule(_ReturnAddress(), hbModule);
	//TODO: Do an md5 checksum on allowed files instead

	HMODULE tmp;
	if (isAllowed)
	{
		//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
		hkLoadLibraryW->disable();
		tmp = origLoadLibraryA(name);
		hkLoadLibraryW->enable();
		return tmp;
	}
	return GetModuleHandle(L"kernel32.dll"); //Returning an handle to the kernel32 module, in order to mess with the injector
} //NB: This hook allows partial block of module injections

void __stdcall hkFnFreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
{
	if (hLibModule == hbModule) //Not allowing unloading our module
	{
		return;
	}

	//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
	hkFreeLibraryAndExitThread->disable();
	origFreeLibraryAndExitThread(hLibModule, dwExitCode);
	hkFreeLibraryAndExitThread->enable();
} //NB: This hook blocks some attacks on the AC's state

BOOL __stdcall hkFnFreeLibrary(HMODULE hLibModule)
{
	if (hLibModule == hbModule) //Not allowing unloading our module
	{
		return false;
	}

	//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
	hkFreeLibrary->disable();
	BOOL tmp = origFreeLibrary(hLibModule);
	hkFreeLibrary->enable();
	return tmp;
} //NB: This hook blocks some attacks on the AC's state

LPVOID hkFnVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID tmp = NULL;
	if (flProtect != PAGE_EXECUTE && flProtect != PAGE_EXECUTE_READ && flProtect != PAGE_EXECUTE_READWRITE && flProtect != PAGE_EXECUTE_WRITECOPY) //We're not allowing VirtualAlloc for executable memory
	{
		//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
		hkVirtualAlloc->disable();
		tmp = origVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
		hkVirtualAlloc->enable();
	}
	return tmp;
} //NB: This hook allows blocking extraction of compressed/encrypted code from a DLL

PVOID hkFnAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
	void* adr = _ReturnAddress(); //Getting the return address, which is the address where the execution will resume afterwards
	if (ModUtils::isInsideModule(adr, hbModule)) //Checking that this function was called from our anticheat module
	{
		//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
		hkAddVectoredExceptionHandler->disable();
		PVOID tmp = AddVectoredExceptionHandler(First, Handler);
		hkAddVectoredExceptionHandler->enable();
		return tmp;
	}
	return NULL;
} //This hook prevents any module from using VEH hooking except ours (we could lay trap areas with this!)