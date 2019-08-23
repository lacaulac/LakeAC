// TestConsole.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "Process.h"
#include <winternl.h>

int pid = 0;

std::vector<MODULEENTRY32> *listedModules;
std::vector<THREADENTRY32> *listedThreads;

typedef enum _OBJECT_INFORMATION_CLASS2 {




	_ObjectBasicInformation,
	_ObjectNameInformation,
	_ObjectTypeInformation,
	_ObjectAllInformation,
	_ObjectDataInformation


} OBJECT_INFORMATION_CLASS2, * POBJECT_INFORMATION_CLASS2;

typedef NTSTATUS(__stdcall* oNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS2 oic, void* ObjectInformation, unsigned long ObjInfoLength, unsigned long* ReturnedLength);

oNtQueryObject _NtQueryObject;

typedef struct _OBJECT_NAME_INFORMATION {



	UNICODE_STRING          Name;
	WCHAR                   NameBuffer[0];

} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	NonPagedPoolExecute,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolBase,
	NonPagedPoolBaseMustSucceed,
	NonPagedPoolBaseCacheAligned,
	NonPagedPoolBaseCacheAlignedMustS,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession,
	NonPagedPoolNx,
	NonPagedPoolNxCacheAligned,
	NonPagedPoolSessionNx
} POOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {




	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;



} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION {




	ULONG                   NumberOfObjectsTypes;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];



} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;


int main()
{
	/*
	LoadLibraryA("kernel32.dll");
	char lib[12] = "kernel32.dl";
	lib[11] = 'l';
	if (LoadLibraryA(lib))
		printf("Not debugged.\n");
	else
		printf("Debugged.\n");
		*/
	std::cout << "Size of HMODULE on x64: " << sizeof(HMODULE) << std::endl;
	std::cout << "Size of FARPROC on x64: " << sizeof(FARPROC) << std::endl;
	std::cout << "Size of LPVOID on x64: " << sizeof(LPVOID) << std::endl;
	std::cout << "Size of SIZE_T on x64: " << sizeof(SIZE_T) << std::endl;
	std::cout << "Size of unsigned int on x64: " << sizeof(unsigned int) << std::endl;
	std::cout << "Size of unsigned long on x64: " << sizeof(unsigned long) << std::endl;
	std::cout << "Welcome to LakeAC console tests" << std::endl;
	std::cout << "Running at " << Process::getCurrentPid() << std::endl;
	std::cout << "PID of the target program: ";
	std::cin >> pid;
	std::cout << "Analysing program with PID " << pid << std::endl;

	_NtQueryObject = (oNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

	Process pr(pid);

	_OBJECT_ALL_INFORMATION* poti;

	unsigned long bufSize = sizeof(_OBJECT_ALL_INFORMATION);
	void* buffer = {};

	NTSTATUS ntstat = _NtQueryObject(pr.getHandle(), _ObjectAllInformation, buffer, 0, &bufSize);
	buffer = malloc(bufSize);
	ntstat = _NtQueryObject(pr.getHandle(), _ObjectAllInformation, buffer, bufSize, NULL);
	poti = (_OBJECT_ALL_INFORMATION*)buffer;

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