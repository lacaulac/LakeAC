#include "pch.h"
#include "HandleWatch.h"
#include <vector>
#include <set>
#include "Process.h"
#include "ntdll_stuff.h"

#define GAME_WINDOW_NAME "TeamSpeak 3"
#define GAME_WINDOW_CLASS NULL

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
				std::vector<PROCESS_HANDLE_TABLE_ENTRY_INFO>* inf = getHandleInfoForProcess(hProcHandle);
				if (inf == nullptr)
					continue;
				for (PROCESS_HANDLE_TABLE_ENTRY_INFO t : *inf)
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
							char msg[100];
							sprintf_s(msg, "Process %d has a handle on us!", pid);
							MessageBoxA(0, msg, "LakeAC Handle Detection", 0);
						}
					}
					CloseHandle(copiedHandle);
				}
				delete inf;
			}
		}
		delete procList;
		Sleep(50);
	}
}