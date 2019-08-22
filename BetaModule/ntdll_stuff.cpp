#include "pch.h"
#include "ntdll_stuff.h"

const long STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* getHandleInfoForProcess(unsigned int pid)
{
	HANDLE hToProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* t = getHandleInfoForProcess(hToProc);
	CloseHandle(hToProc);
	return t;
}

std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* getHandleInfoForProcess(HANDLE remProcess)
{
	oNtQueryInformationProcess _NtQueryInformationProcess = (oNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	unsigned long bufferSize = 0x8000;
	void* buffer = malloc(bufferSize); //Allocates ~32KB of RAM on the heap to store the results
	std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* res = new std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>();

	int attempts = 0;
	NTSTATUS status;
	unsigned long writtenBytes;

	status = _NtQueryInformationProcess(remProcess, ProcessHandleInformation, buffer, bufferSize, &writtenBytes);

	while (status == STATUS_INFO_LENGTH_MISMATCH && attempts <= 8)
	{
		free(buffer);
		bufferSize = writtenBytes;
		buffer = malloc(bufferSize);

		status = _NtQueryInformationProcess(remProcess, ProcessHandleInformation, buffer, bufferSize, &writtenBytes);
		
		attempts++;
	}

	if (!NT_SUCCESS(status))
		return nullptr;

	PROCESS_HANDLE_SNAPSHOT_INFORMATION* result = (PROCESS_HANDLE_SNAPSHOT_INFORMATION *)buffer;

	for (int i = 0; i < result->NumberOfHandles; i++)
	{
		res->push_back(result->Handles[i]);
	}

	free(buffer);
	
	return res;
}
