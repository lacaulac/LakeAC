#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#pragma once

//This class allows for easy retrieving of information on modules and shit
class Process
{
public:
	Process(int p_pid); //Creates the object
	std::vector<MODULEENTRY32>* GetModules(); //Gets a list of the declared modules into a std::vector
 	std::vector<THREADENTRY32>* GetThreads(); //Gets a list of the threads into a std::vector
	std::vector<unsigned int>* GetAllPids(); //Gets a list of all the running processes's PIDs
	static unsigned int getCurrentPid(); //Gets the current process's PID (Kinda useless since it's just a wrapper for GetCurrentProcessId.
	BYTE* dumpModule(MODULEENTRY32 mod); //A now for something exciting. Dumps a module! In a REAAAAALLY shitty way, but still dumps !
private:
	int pid;
	HANDLE procHandle;
};

