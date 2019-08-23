// TestInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

bool inject(char* path, unsigned long pid);

int main()
{
	char* buff = (char*)calloc(255, 1);
	unsigned long targetPid;

    std::cout << "Hello World!\n";
	std::cout << "PID: ";
	std::cin >> targetPid;
	std::cout << "DLL name:";
	std::cin >> buff;

	if (inject(buff, targetPid))
	{
		std::cout << "Successful injection into " << targetPid << std::endl;
	}
	else
	{
		std::cout << "Couldn't inject into " << targetPid << std::endl;
		DWORD err = GetLastError();
		auto t = 3;
	}

	free(buff);

	return 0;
}

bool inject(char* path, unsigned long pid)
{
	HANDLE procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
	if (procHandle == NULL)
		return false;

	printf("[INJECTION] Got a handle to %d\n", pid);

	PVOID dllNameAdr = VirtualAllocEx(procHandle, NULL, strlen(path) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (dllNameAdr == NULL)
		return false;

	printf("[INJECTION] Got %d bytes into %d\n", strlen(path) + 1, pid);

	if (WriteProcessMemory(procHandle, dllNameAdr, path, strlen(path) + 1, NULL) == NULL)
		return false;

	printf("[INJECTION] Wrote %d bytes into %d\n", strlen(path) + 1, pid);

	HANDLE tHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), dllNameAdr, 0, 0);
	if (tHandle == NULL)
		return false;

	printf("[INJECTION] Started LoadLibraryA into %d\n", pid);
	WaitForSingleObject(tHandle, INFINITE);
	printf("[INJECTION] Finished the injection into %d\n", pid);


	return true;
}
