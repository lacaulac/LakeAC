// TestConsole.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "Process.h"

int pid = 0;

std::vector<MODULEENTRY32> *listedModules;
std::vector<THREADENTRY32> *listedThreads;

int main()
{
	LoadLibraryA("kernel32.dll");
	char lib[12] = "kernel32.dl";
	lib[11] = 'l';
	if (LoadLibraryA(lib))
		printf("Not debugged.\n");
	else
		printf("Debugged.\n");

	std::cout << "Size of HMODULE on x64: " << sizeof(HMODULE) << std::endl;
	std::cout << "Size of FARPROC on x64: " << sizeof(FARPROC) << std::endl;
	std::cout << "Size of LPVOID on x64: " << sizeof(LPVOID) << std::endl;
	std::cout << "Size of SIZE_T on x64: " << sizeof(SIZE_T) << std::endl;
	std::cout << "Welcome to LakeAC console tests" << std::endl;
	std::cout << "Running at " << Process::getCurrentPid() << std::endl;
	std::cout << "PID of the target program: ";
	std::cin >> pid;
	std::cout << "Analysing program with PID " << pid << std::endl;

	Process pr(pid);

	listedModules = pr.GetModules();
	listedThreads = pr.GetThreads();

	std::cout << "Displaying modules" << std::endl;
	int counter = 0;
	for (MODULEENTRY32 mod : *listedModules)
	{
		std::cout << "===MODULE===" << std::endl;
		std::cout << "Index: " << counter << std::endl;
		std::wcout << "Name:  " << mod.szModule << std::endl;
		std::wcout << "Path:  " << mod.szExePath << std::endl;
		std::wcout << "Size:  " << mod.modBaseSize << " bytes" << std::endl;
		std::cout << std::endl;

		counter++;

		if (wcscmp(mod.szModule, TEXT("VCRUNTIME140D.dll")) == 0)
		{
			
		}
	}
	std::string ans = "nope";

	std::cout << "Do you want to dump a module? (y/N)" << std::endl;
	std::cin >> ans;

	while ((ans.compare("y") == 0) || (ans.compare("Y") == 0))
	{
		int modNumber;
		printf("Module id: ");
		std::cin >> modNumber;
		if (modNumber < 0 || modNumber >= listedModules->size())
		{
			printf("Invalid identifier. Please try again.\n");
			continue;
		}
		MODULEENTRY32 mod = listedModules->at(modNumber);
		
		char finalName[120];
		char buf[40];
		wcstombs_s(NULL, buf, mod.szModule, 40);
		sprintf_s(finalName, "dump_%s", buf);

		std::wcout << "Dumping " << mod.szModule << " into " << finalName << " ." << std::endl;
		FILE* dumpFile;
		fopen_s(&dumpFile, finalName, "w");
		BYTE* dump = pr.dumpModule(mod);
		size_t written = fwrite(dump, 1, mod.modBaseSize, dumpFile);
		printf("%d bytes were written to dump.dll.\n", written);
		fclose(dumpFile);


		std::cout << "Do you want to dump another module? (y/N)" << std::endl;
		std::cin >> ans;
	} 

	return 0;
}