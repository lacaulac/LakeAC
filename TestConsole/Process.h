#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#pragma once


class Process
{
public:
	Process(int p_pid);
	std::vector<MODULEENTRY32>* GetModules();
	std::vector<THREADENTRY32>* GetThreads();
	static unsigned int getCurrentPid();
	BYTE* dumpModule(MODULEENTRY32 mod);
private:
	int pid;
	HANDLE procHandle;
};

