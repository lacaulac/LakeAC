#include "pch.h"
#include "Main.h"
#include "Hook.h"
#include "Process.h"
#include <iostream>
#include <Windows.h>
#include <processthreadsapi.h>
#include <intrin.h>
#include <set>
#include "ModUtils.h"
#include <winternl.h>
#include <handleapi.h>
#include "ntdll_stuff.h"

#define THREAD_MANIP_FAIL ((DWORD)-1) //To verify that we paused/resumed a thread (using SuspendThread)

HMODULE __stdcall hkFnLoadLibraryW(LPCWSTR name); //The signature of our hook
Hook* hkLoadLibraryW; //The hook object pointer, will be linked further down
typedef HMODULE(__stdcall* oLoadLibraryW)(LPCWSTR); //The mandatory typedef of the original function, so that we don't have to rely on inline assembly to call the original function

HMODULE __stdcall hkFnLoadLibraryA(LPCSTR name);
Hook* hkLoadLibraryA;
typedef HMODULE(__stdcall* oLoadLibraryA)(LPCSTR);

void __stdcall hkFnFreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode);
Hook* hkFreeLibraryAndExitThread;
typedef void(__stdcall* oFreeLibraryAndExitThread)(HMODULE, DWORD);

BOOL __stdcall hkFnFreeLibrary(HMODULE hLibModule);
Hook* hkFreeLibrary;
typedef BOOL(__stdcall* oFreeLibrary)(HMODULE);

LPVOID hkFnVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
Hook* hkVirtualAlloc;
typedef LPVOID(__stdcall* oVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

PVOID hkFnAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
Hook* hkAddVectoredExceptionHandler;
typedef PVOID(__stdcall* oAddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);

oNtQuerySystemInformation WNtQuerySystemInformation;
oNtQueryInformationProcess WNtQueryInformationProcess;


oLoadLibraryW origLoadLibraryW; //A pointer to the original LoadLibraryW address. Using the oLoadLibraryW typedef from line 15
oLoadLibraryA origLoadLibraryA;
oFreeLibraryAndExitThread origFreeLibraryAndExitThread;
oFreeLibrary origFreeLibrary;
oVirtualAlloc origVirtualAlloc;
oAddVectoredExceptionHandler origAddVectoredExceptionHandler;


//Process information objects
Process* thisProcess;
std::vector<THREADENTRY32>* threads;
std::vector<MODULEENTRY32>* modules;

//A reference to our module's base address for being able to verify if we're the target of some aggressive actions and/or if a WinAPI call originated from our module
HMODULE anticheatModule;

//A vector to store all the initialised hooks. Used to verify if our hooks haven't been trifled with
std::vector<Hook*> hooks;

//A hook checking thread. Constantly checks if the hooks are still intact
DWORD __stdcall HookCheckThread(LPVOID parameter);
DWORD __stdcall HandleCheckThread(LPVOID parameter);

//The main thread
DWORD WINAPI MainThread(LPVOID parameter)
{
#if NDEBUG
	if (IsDebuggerPresent())
	{
		ExitProcess(420);
	}
#else
	MessageBoxA(0, "Hey! You can now attach your debugger!", "LakeAC Alpha", MB_ICONEXCLAMATION);
#endif // DEBUG

	
	anticheatModule = GetModuleHandleA("BetaModule.dll"); //Gets the module handle to our module
	thisProcess = new Process(Process::getCurrentPid()); //Initialises the process info object
	modules = thisProcess->GetModules(); //Gets a list of the current modules

	WNtQuerySystemInformation = (oNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	WNtQueryInformationProcess = (oNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	

	//Linking the original function addresses to the function pointers (declarations around line 40)
	origLoadLibraryW = (oLoadLibraryW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	origLoadLibraryA = (oLoadLibraryA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	origFreeLibraryAndExitThread = (oFreeLibraryAndExitThread)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibraryAndExitThread");
	origFreeLibrary = (oFreeLibrary)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
	origVirtualAlloc = (oVirtualAlloc)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
	origAddVectoredExceptionHandler = (oAddVectoredExceptionHandler)GetProcAddress(GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");
	
	//Creation of the hook objects
	hkLoadLibraryW = new Hook((FARPROC)origLoadLibraryW, (FARPROC)&hkFnLoadLibraryW);
	hkLoadLibraryA = new Hook((FARPROC)origLoadLibraryA, (FARPROC)&hkFnLoadLibraryA);
	hkFreeLibraryAndExitThread = new Hook((FARPROC)origFreeLibraryAndExitThread, (FARPROC)&hkFnFreeLibraryAndExitThread);
	hkFreeLibrary = new Hook((FARPROC)origFreeLibrary, (FARPROC)&hkFnFreeLibrary);
	hkVirtualAlloc = new Hook((FARPROC)origVirtualAlloc, (FARPROC)&hkFnVirtualAlloc);
	hkAddVectoredExceptionHandler = new Hook((FARPROC)origAddVectoredExceptionHandler, (FARPROC)& hkFnAddVectoredExceptionHandler);

	//Adding the hooks created previously into a vector<Hook*>
	hooks.push_back(hkLoadLibraryA);
	hooks.push_back(hkLoadLibraryW);
	hooks.push_back(hkFreeLibraryAndExitThread);
	hooks.push_back(hkFreeLibrary);
	hooks.push_back(hkVirtualAlloc);
	hooks.push_back(hkAddVectoredExceptionHandler);

	//Toggling all the hooks on and verifying if the hooks were successfully toggled on
	bool areHooksInitialised = true;
	for (Hook* hk : hooks)
	{
		areHooksInitialised = areHooksInitialised & hk->enable();
	}

	//We should be done initialising
	if (areHooksInitialised)
	{
		MessageBox(0, L"Anti-cheat loaded", L"Lake AC Alpha", 0); //Everything's good to go
	}
	else
	{
		MessageBox(0, L"Couldn't setup hooks", L"Lake AC Alpha", 0); //Something didn't work, gotta exit
		ExitProcess(420);
	}

	//Starting the hook checking thread
	CreateThread(0, 0, &HookCheckThread, &hooks, 0, 0);
	CreateThread(0, 0, &HandleCheckThread, NULL, 0, 0);

	/*
	thisProcess = new Process(Process::getCurrentPid());
	threads = thisProcess->GetThreads();
	for (THREADENTRY32 th : *threads)
	{
		HANDLE tHandle = OpenThread(THREAD_ALL_ACCESS, false, th.th32ThreadID);
		if (tHandle != INVALID_HANDLE_VALUE)
		{
			if (SuspendThread(tHandle) != THREAD_MANIP_FAIL)
			{
				CONTEXT tContext;
				if (GetThreadContext(tHandle, &tContext))
				{
					Sleep(1);
					char t[50];
					sprintf_s(t, "Thread %d is at 0x%16x", th.th32ThreadID, tContext.Rip);
					MessageBoxA(0, t, "Thread info", MB_ICONINFORMATION);
				}
				ResumeThread(tHandle);
				CloseHandle(tHandle);
			}
			else
			{
				MessageBoxA(0, "Couldn't put the thread to sleep", "Error", MB_ICONERROR);
			}
			
		}
		else
		{
			MessageBoxA(0, "Couldn't get ahold of da thread handle", "Error", MB_ICONERROR);
		}
		
	}
	//Utiliser OpenThread et GetThreadContext pour analyser les threads
	//*/

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
	bool isAllowed = (strcmp(name, "DummyDLL.dll") != NULL) | ModUtils::isInsideModule(_ReturnAddress(), anticheatModule);
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
	if (hLibModule == anticheatModule) //Not allowing unloading our module
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
	if (hLibModule == anticheatModule) //Not allowing unloading our module
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
	if (ModUtils::isInsideModule(adr, anticheatModule)) //Checking that this function was called from our anticheat module
	{
		//Disabling and enabling back the hook in order to use the original function. Not the best solution but works
		hkAddVectoredExceptionHandler->disable();
		PVOID tmp = AddVectoredExceptionHandler(First, Handler);
		hkAddVectoredExceptionHandler->enable();
		return tmp;
	}
	return NULL;
} //This hook prevents any module from using VEH hooking except ours (we could lay trap areas with this!)

DWORD __stdcall HookCheckThread(LPVOID parameter)
{
	
	//MessageBoxA(0, "Started checking for modified hooks :)", "LakeAC Alpha Info", MB_ICONASTERISK); //Debug message
	std::vector<Hook*>* hooks = (std::vector<Hook*> * )parameter; //Getting the vector<Hook*> containing all the (non-)active hooks
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

DWORD __stdcall HandleCheckThread(LPVOID parameter)
{
	std::set<unsigned int> foundPids;
	while (true)
	{
		std::vector<unsigned long>* procList = thisProcess->GetAllPids();
		if (procList != nullptr)
		{
			for (unsigned long pid : *procList)
			{
				if (foundPids.count(pid) != 0)
					continue;
				HANDLE hProcHandle = GetHandleInfoHandleForProcess(pid);
				std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* inf = getHandleInfoForProcess(hProcHandle);
				if (inf == nullptr)
					continue;
				for (PROCESS_HANDLE_TABLE_ENTRY_INFO t : *inf)
				{
					if (t.ObjectTypeIndex != 7)
						continue;
					HANDLE copiedHandle;
					DuplicateHandle(hProcHandle, t.HandleValue, GetCurrentProcess(), &copiedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
					if ((wrapCompareObjectHandles(copiedHandle, GetCurrentProcess())) && (pid != GetCurrentProcessId()))
					{
						//Analyse handle rights. If it can write/read/createthread, then hook/dump/beat the shit out of it
						if (((t.GrantedAccess && PROCESS_VM_READ) || (t.GrantedAccess && PROCESS_VM_WRITE) || (t.GrantedAccess && PROCESS_CREATE_THREAD) || (t.GrantedAccess && PROCESS_SUSPEND_RESUME) || (t.GrantedAccess && PROCESS_VM_OPERATION)))
						{
							foundPids.insert(pid);
							char msg[100];
							sprintf_s(msg, "Process %d has a handle on us!", pid);
							MessageBoxA(0, msg, "LakeAC Handle Detection", 0);
						}
					}
					CloseHandle(copiedHandle);
				}
				delete inf;
			}
		}
		delete procList;
		Sleep(50);
	}
}