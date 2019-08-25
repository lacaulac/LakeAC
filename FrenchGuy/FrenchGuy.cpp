#include "pch.h"
#include "FrenchGuy.h"
#include "Hook.h"
#include "../shared/ntdll_stuff.h"
#include "../gamedefs.h"
#include "../shared/ModUtils.h"
#include "../shared/PEManager.h"

typedef NTSTATUS(__stdcall* oNtReadVirtualMemory)(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToRead, unsigned long* readBytes);
typedef NTSTATUS(__stdcall* oNtWriteVirtualMemory)(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToWrite, unsigned long* wroteBytes);
//typedef NTSTATUS(__stdcall* oNtProtectVirtualMemory)(HANDLE procHandle, void* targetAddress, unsigned long* numberOfBytesToProtect, unsigned long newProtection, unsigned long* oldProtection);
//typedef NTSTATUS(__stdcall* oNtAllocateVirtualMemory)(HANDLE procHandle, void* baseAddress, unsigned long UNUSEDZeroBitsUNUSED, unsigned long* regionSize, unsigned long allocType, unsigned long protect);
typedef void* (__stdcall* oVirtualAllocEx)(HANDLE procHandle, void* targetAddress, SIZE_T dwSize, DWORD allocType, DWORD protection);
typedef HANDLE(__stdcall* oCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef BOOL(__stdcall* oVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

NTSTATUS hkFnNtReadVirtualMemory(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToRead, unsigned long* readBytes);
NTSTATUS hkFnNtWriteVirtualMemory(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToWrite, unsigned long* wroteBytes);
void* hkFnVirtualAllocEx(HANDLE procHandle, void* targetAddress, SIZE_T dwSize, DWORD allocType, DWORD protection);
HANDLE hkFnCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
BOOL hkFnVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

void SendMd5Hashes(void* origAddress);

oNtReadVirtualMemory origNtReadVirtualMemory;
oNtWriteVirtualMemory origNtWriteVirtualMemory;
oVirtualAllocEx origVirtualAllocEx;
oCreateRemoteThread origCreateRemoteThread;
oVirtualProtectEx origVirtualProtectEx;

//TODO Add a hook for VirtualProtect in order to protect our own module
Hook* hkNtReadVirtualMemory, * hkNtWriteVirtualMemory, * hkVirtualAllocEx, * hkCreateRemoteThread, * hkVirtualProtectEx;

std::vector<Hook*> hooks;

HANDLE gameHandle;

void FrenchGuyThread(LPVOID parameter)
{
	//Get a basic handle to the game in order to compare the suspect's handles to ours and determine if our game is the target
	HWND windowHandle = FindWindowA(GAME_WINDOW_CLASS, GAME_WINDOW_NAME);
	unsigned long gamePid;
	GetWindowThreadProcessId(windowHandle, &gamePid);

	gameHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, gamePid);

	//Reference all original function addresse
	origNtReadVirtualMemory = (oNtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	origNtWriteVirtualMemory = (oNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	origVirtualAllocEx = (oVirtualAllocEx)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx");
	origCreateRemoteThread = (oCreateRemoteThread)GetProcAddress(GetModuleHandleA("kernel32.dl"), "CreateRemoteThread");
	origVirtualProtectEx = (oVirtualProtectEx)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualProtectEx");

	//Create all hooks
	hkNtReadVirtualMemory = new Hook((FARPROC)origNtReadVirtualMemory, (FARPROC)&hkFnNtReadVirtualMemory);
	hkNtWriteVirtualMemory = new Hook((FARPROC)origNtWriteVirtualMemory, (FARPROC)&hkFnNtWriteVirtualMemory);
	hkCreateRemoteThread = new Hook((FARPROC)origCreateRemoteThread, (FARPROC)&hkFnCreateRemoteThread);
	hkVirtualAllocEx = new Hook((FARPROC)origVirtualAllocEx, (FARPROC)&hkFnVirtualAllocEx);
	hkVirtualProtectEx = new Hook((FARPROC)origVirtualProtectEx, (FARPROC)&hkFnVirtualProtectEx);

	//Start all hooks
	hooks.push_back(hkNtReadVirtualMemory);
	hooks.push_back(hkNtWriteVirtualMemory);
	hooks.push_back(hkVirtualAllocEx);
	hooks.push_back(hkVirtualProtectEx);
	hooks.push_back(hkCreateRemoteThread);

	bool areHooksInitialised = true;
	for (Hook* hk : hooks)
	{
		areHooksInitialised = areHooksInitialised & hk->enable();
	}

	if (!areHooksInitialised)
		ExitProcess(-1);

	//If can't start all hooks, close process.

	//TODO Check hooks maybe?
}

NTSTATUS hkFnNtReadVirtualMemory(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToRead, unsigned long* readBytes)
{
	if (wrapCompareObjectHandles(procHandle, gameHandle))
	{
		SendMd5Hashes(_ReturnAddress());
		for (unsigned long i = 0; i < numberOfBytesToRead; i++) //F*ck'em up a bit amirite
		{
			((char*)buffer)[i] = 0xcc;
		}
		return 0;
	}
	hkNtReadVirtualMemory->disable();
	NTSTATUS tmp = origNtReadVirtualMemory(procHandle, targetAddress, buffer, numberOfBytesToRead, readBytes);
	hkNtReadVirtualMemory->enable();
	return tmp;
}

NTSTATUS hkFnNtWriteVirtualMemory(HANDLE procHandle, void* targetAddress, void* buffer, unsigned long numberOfBytesToWrite, unsigned long* wroteBytes)
{
	if (wrapCompareObjectHandles(procHandle, gameHandle))
	{
		SendMd5Hashes(_ReturnAddress());
		return 0;
	}
	hkNtWriteVirtualMemory->disable();
	NTSTATUS tmp = origNtWriteVirtualMemory(procHandle, targetAddress, buffer, numberOfBytesToWrite, wroteBytes);
	hkNtWriteVirtualMemory->enable();
	return tmp;
}

void* hkFnVirtualAllocEx(HANDLE procHandle, void* targetAddress, SIZE_T dwSize, DWORD allocType, DWORD protection)
{
	if (wrapCompareObjectHandles(procHandle, gameHandle))
	{
		SendMd5Hashes(_ReturnAddress());
		return nullptr;
	}
	hkVirtualAllocEx->disable();
	void* tmp = origVirtualAllocEx(procHandle, targetAddress, dwSize, allocType, protection);
	hkVirtualAllocEx->enable();
	return tmp;
}

HANDLE hkFnCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	if (wrapCompareObjectHandles(hProcess, gameHandle))
	{
		SendMd5Hashes(_ReturnAddress());
		return hProcess;
	}
	hkCreateRemoteThread->disable();
	void* tmp = origCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	hkCreateRemoteThread->enable();
	return tmp;
}

BOOL hkFnVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	if (wrapCompareObjectHandles(hProcess, gameHandle))
	{
		SendMd5Hashes(_ReturnAddress());
		return 42;
	}
	hkVirtualProtectEx->disable();
	BOOL tmp = origVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	hkVirtualProtectEx->enable();
	return tmp;
}

void SendMd5Hashes(void* origAddress)
{
	MODULEENTRY32 srcMod = ModUtils::getOriginModule(origAddress);
	std::vector<md5_hash> hash = PEManager::hashSection(srcMod.hModule, ".text");
	//TODO Send those to a server!
}
