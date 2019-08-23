#include "pch.h"
#include "ModUtils.h"

bool ModUtils::isInsideModule(void* ptr, HMODULE mod)
{
	Process tmp(GetCurrentProcessId()); //Creates an object to help getting intel on the modules
	std::vector<MODULEENTRY32>* vecMod = tmp.GetModules();
	for (MODULEENTRY32 modT : *vecMod) //Walks through the module list
	{
		if ((void*)modT.modBaseAddr == (void*)mod) //If we found a module that has the same base address as the one specified in the parameters, then we've found our module!
		{
			delete vecMod;
			return isInsideModule(ptr, modT); //Goes to the next step
		}
	}
	delete vecMod;
	return false;
}

bool ModUtils::isInsideModule(void* ptr, MODULEENTRY32 mod)
{
	return isInsideModule(ptr, mod.modBaseAddr, mod.modBaseAddr + mod.modBaseSize); //Just skips to the if-wrapper
}

MODULEENTRY32* ModUtils::getOriginModule(void* ptr)
{
	Process tmp(GetCurrentProcessId()); //Creates an object to help getting intel on the modules
	std::vector<MODULEENTRY32>* vecMod = tmp.GetModules();
	for (MODULEENTRY32 mod : *vecMod)
	{
		if (isInsideModule(ptr, mod))
			return &mod;
	}
	return NULL;
}


bool ModUtils::isInsideModule(void* ptr, void* begin, void* end)
{
	return ptr >= begin && ptr < end; //SUPRISE! It's not even an if. Just a simple f-ing condition :)
}
