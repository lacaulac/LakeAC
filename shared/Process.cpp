#include "Process.h"

Process::Process(int p_pid)
{
	pid = p_pid;
	if ((procHandle = OpenProcess(PROCESS_VM_READ, false, pid)) == NULL) //Tries to open a handle on a given process
	{
		std::cout << "Failed to get a handle on " << pid << std::endl;
	}
}

std::vector<MODULEENTRY32>* Process::GetModules()
{
	std::vector<MODULEENTRY32>* listedModules = new std::vector<MODULEENTRY32>(); //Creates a std::vector<MODULEENTRY>
	HANDLE snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); //Takes a quite nice photograph of all the modules
	MODULEENTRY32 moduleEntry32; //This will store the intel we've got about a module
	if (snapHandle == INVALID_HANDLE_VALUE) //If the snapshot failed
	{
		std::cout << "Couldn't get a snapshot of the process's module list" << std::endl;
		return nullptr;
	}
	moduleEntry32.dwSize = sizeof(MODULEENTRY32); //Initialisation, dunno why it's not done by Module32First but whatever
	if (!Module32First(snapHandle, &moduleEntry32)) //Try to get the first module of the snapshot
	{
		std::cout << "Couldn't find any module for " << pid << std::endl;
		return nullptr; //Quit if we couldn't
	}
	do //Oh, we got there! Means that we've found at least a module after all
	{
		listedModules->push_back(moduleEntry32); //Let's store it into our vector :)
	} while (Module32Next(snapHandle, &moduleEntry32)); //And do that for as long as we can find modules
	CloseHandle(snapHandle); //Time to go :)

	return listedModules; //And there goes the vector. It's quite a nice gun, I like it.
}

std::vector<THREADENTRY32>* Process::GetThreads()
{ //OMG STOLEN PROCEDURE FROM MSDN IWKIWI !!!!!!!!! SO BAAAAD
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

std::vector<unsigned long>* Process::GetAllPids()
{
	std::vector<unsigned long>* listedPids = new std::vector<unsigned long>();
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return listedPids;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return listedPids;
	}

	do
	{
		listedPids->push_back(pe32.th32ProcessID);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return listedPids;
}

unsigned int Process::getCurrentPid()
{
	return (unsigned int)GetCurrentProcessId(); //I mean...
}

BYTE* Process::dumpModule(MODULEENTRY32 mod)
{
	BYTE* buffer = (BYTE*)malloc((size_t)mod.modBaseSize); //Creates a buffer the size of the in-memory module
	size_t readBytes = NULL; //Gonna store how much bytes were read
	ReadProcessMemory(procHandle, mod.modBaseAddr, (LPVOID)buffer, mod.modBaseSize, &readBytes); //Copies the module into the buffer
	if (readBytes != mod.modBaseSize) //Check if we've got the right amount of data
	{
		printf("Read %d bytes instead of %d bytes.\n", readBytes, mod.modBaseSize);
	}
	return buffer; //And there we go
}
