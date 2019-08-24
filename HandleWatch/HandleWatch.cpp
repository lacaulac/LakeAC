#include "pch.h"
#include "HandleWatch.h"
#include <vector>
#include <set>
#include "Process.h"
#include "ntdll_stuff.h"
#include "../gamedefs.h"

bool inject(char* path, unsigned long pid);

void MainThread(LPVOID parameter)
{
	HWND windowHandle = FindWindowA(GAME_WINDOW_CLASS, GAME_WINDOW_NAME);
	unsigned long targetPid;
	GetWindowThreadProcessId(windowHandle, &targetPid);

	Process* thisProcess = new Process(targetPid);
	std::set<unsigned int> foundPids;
	while (true)
	{
		std::vector<unsigned long>* procList = thisProcess->GetAllPids();
		if (procList != nullptr)
		{
			for (unsigned long pid : *procList)
			{
				if (foundPids.count(pid) != 0)
					continue;
				HANDLE hProcHandle = GetHandleInfoHandleForProcess(pid);
				std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO> inf = getHandleInfoForProcess(hProcHandle);
				if (inf.empty())
					continue;
				for (PROCESS_HANDLE_TABLE_ENTRY_INFO t : inf)
				{
					if (t.ObjectTypeIndex != 7)
						continue;
					HANDLE copiedHandle;
					DuplicateHandle(hProcHandle, t.HandleValue, GetCurrentProcess(), &copiedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
					if ((wrapCompareObjectHandles(copiedHandle, GetCurrentProcess())) && (pid != GetCurrentProcessId()) && (pid != targetPid))
					{
						//Analyse handle rights. If it can write/read/createthread, then hook/dump/beat the shit out of it
						if (((t.GrantedAccess && PROCESS_VM_READ) || (t.GrantedAccess && PROCESS_VM_WRITE) || (t.GrantedAccess && PROCESS_CREATE_THREAD) || (t.GrantedAccess && PROCESS_SUSPEND_RESUME) || (t.GrantedAccess && PROCESS_VM_OPERATION)))
						{
							foundPids.insert(pid);
							if (!inject((char*)"D:\\Documents\\LakeAC\\x64\\Release\\FrenchGuy.dll", pid))
							{
								HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
								CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"), (LPVOID)420, 0, 0);
							}
							break;
						}
					}
					CloseHandle(copiedHandle);
				}
				inf.clear();
			}
		}
		delete procList;
		Sleep(100);
	}
}

bool inject(char* path, unsigned long pid)
{
	HANDLE procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, false, pid);
	if (procHandle == NULL)
		return false;

	PVOID dllNameAdr = VirtualAllocEx(procHandle, NULL, strlen(path) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (dllNameAdr == NULL)
		return false;

	if (WriteProcessMemory(procHandle, dllNameAdr, path, strlen(path) + 1, NULL) == NULL)
		return false;

	HANDLE tHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), dllNameAdr, 0, 0);
	if (tHandle == NULL)
		return false;
	return true;
}