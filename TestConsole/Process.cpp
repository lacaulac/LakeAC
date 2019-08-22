#include "Process.h"

Process::Process(int p_pid)
{
	pid = p_pid;
	if ((procHandle = OpenProcess(PROCESS_VM_READ, false, pid)) == NULL)
	{
		std::cout << "Failed to get a handle on " << pid << std::endl;
	}
}

std::vector<MODULEENTRY32>* Process::GetModules()
{
	std::vector<MODULEENTRY32>* listedModules = new std::vector<MODULEENTRY32>();
	HANDLE snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32 moduleEntry32;
	if (snapHandle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Couldn't get a snapshot of the process's module list" << std::endl;
		return nullptr;
	}
	moduleEntry32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapHandle, &moduleEntry32))
	{
		std::cout << "Couldn't find any module for " << pid << std::endl;
		return nullptr;
	}
	do
	{
		listedModules->push_back(moduleEntry32);
	} while (Module32Next(snapHandle, &moduleEntry32));
	CloseHandle(snapHandle);

	return listedModules;
}

std::vector<THREADENTRY32>* Process::GetThreads()
{
	std::vector<THREADENTRY32>* listedThreads = new std::vector<THREADENTRY32>();
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return nullptr;

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return nullptr;
	}

	// Now walk the thread list of the system
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			listedThreads->push_back(te32);
		}
	} while (Thread32Next(hThreadSnap, &te32));


	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return listedThreads;
}

unsigned int Process::getCurrentPid()
{
	return (unsigned int)GetCurrentProcessId();;
}

BYTE* Process::dumpModule(MODULEENTRY32 mod)
{
	BYTE* buffer = (BYTE*)malloc((size_t)mod.modBaseSize);
	size_t readBytes = NULL;
	ReadProcessMemory(procHandle, mod.modBaseAddr, (LPVOID)buffer, mod.modBaseSize, &readBytes);
	if (readBytes != mod.modBaseSize)
	{
		printf("Read %d bytes instead of %d bytes.\n", readBytes, mod.modBaseSize);
	}
	return buffer;
}
