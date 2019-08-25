#pragma once
#include <Windows.h>
#include "Process.h"
#include <TlHelp32.h>


class ModUtils
{
public:
	//These two methods allows one to check if a pointed byte is contained inside of a module, with different parameters
	static bool isInsideModule(void* ptr, HMODULE mod);
	static bool isInsideModule(void* ptr, MODULEENTRY32 mod);

	static MODULEENTRY32* getOriginModule(void* ptr); //Gets the module which contains a given address 
private:
	//This is a stupid if-wrapper function.
	static bool isInsideModule(void* ptr, void* begin, void* end);

};

