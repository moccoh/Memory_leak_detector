#include <windows.h>
#include <iostream>
#include <stdlib.h>;
#include <string>
#include <stdio.h>
#include <malloc.h>
#include <Tlhelp32.h>


long processNameToPid(char* processName);
bool CreateProcessandInject(char* dllPath, void* pLoadLibrary, char* proccesPath);
int injectDLL(long pid, char* dllPath, void* pLoadLibrary);

int main(int argc, char *argv[])
{
	char* dllPath = "MemoryHook.dll";
	void* pLoadLibrary = (void*)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"); //get the adress of LoadLibrary(DLL)

	if (argc < 2)
	{
		printf("Put the full path for run");
		Sleep(3000);
		return -1;
	}
	else if(argc > 2)
	{
		if (injectDLL(processNameToPid(argv[1]), dllPath, pLoadLibrary) == -1) { // We inject the DLL into the process
			printf("Problem in injectDLL");
			return -1;
		}
	}
	else
	{
		CreateProcessandInject(dllPath, pLoadLibrary, argv[1]); 
	}

	system("pause");
	return 0;
}

bool CreateProcessandInject(char* dllPath, void* pLoadLibrary, char* proccesName)
{
	std::cout << "LoadLibrary:0x" << std::hex << pLoadLibrary << std::dec << "\nCreating the target process... \n";
	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(startupInfo));

	if (!CreateProcessA(0, proccesName, 0, 0, 1, CREATE_NEW_CONSOLE, 0, 0,
		&startupInfo, &processInformation))
	{
		std::cout << "Could not run the target process. GetLastError() = " << GetLastError();
		return 0;
	}


	std::cout << "Allocating virtual memory ...\n"; //To write in the name of the dll (see the report to explanation)
	void* pReservedSpace = VirtualAllocEx(processInformation.hProcess, NULL, strlen(dllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pReservedSpace)
	{
		std::cout << "Could not allocate virtual memory. GetLastError() = " << GetLastError();
		return 0;
	}

	std::cout << "Writing process memory ...\n";
	if (!WriteProcessMemory(processInformation.hProcess, pReservedSpace, dllPath, strlen(dllPath), NULL))
	{
		std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError();
		return 0;
	}

	std::cout << "Creating remote thread ...\n"; //create thread inside the target
	HANDLE hThread = CreateRemoteThread(processInformation.hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		pReservedSpace,
		0,
		NULL);
	if (!hThread)
	{
		std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError();
		return 0;
	}

	std::cout << "Thread created.\n";

	WaitForSingleObject(hThread, INFINITE); //wait until the end of the thread
	VirtualFreeEx(processInformation.hProcess, pReservedSpace, strlen(dllPath), MEM_COMMIT);

	std::cout << "Done.";
	return 1;
}

int injectDLL(long pid, char* dllPath, void* pLoadLibrary)
{
	long pathSize;
	HANDLE hProcess;
	LPVOID hMemory;
	LPTHREAD_START_ROUTINE hLoadLibraryA;
	HANDLE hRemoteThread;
	DWORD lpThreadId;

	printf(" Open the process. \n");

	pathSize = strlen(dllPath) + 1;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // We open the process
	if (!hProcess)
		return -1;

	std::cout << "Allocating virtual memory ...\n";
	void* pReservedSpace = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pReservedSpace)
	{
		std::cout << "Could not allocate virtual memory. GetLastError() = " << GetLastError();
		return 0;
	}

	std::cout << "Writing process memory ...\n";
	hMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // We allocate memory IN the process
	if (!hMemory)
		return -1;

	if (!WriteProcessMemory(hProcess, hMemory, dllPath, pathSize, 0)) // We write the DLL full path in the memory allocated (it will be the argument of LoadLibraryA)
	{
		std::cout << "Error while calling WriteProcessMemory(). GetLastError() = " << GetLastError();
		return 0;
	}

	std::cout << "Creating remote thread ...\n";

	hLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA"); // We get the address of LoadLibraryA function

	hRemoteThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)pLoadLibrary,
		hMemory,
		0,
		&lpThreadId); // We execute LoadLibraryA function with the DLL full path as argument in the remote process through a new remote thread
	if (!hRemoteThread) {
		std::cout << "Unable to create the remote thread. GetLastError() = " << GetLastError();
		return 0;
	}

	WaitForSingleObject(hRemoteThread, INFINITE);
	VirtualFreeEx(hProcess, hMemory, 0, MEM_DECOMMIT);

	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);

	return 0;
}

long processNameToPid(char* processName)
{
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 lppe = { 0 };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	lppe.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return -1;

	if (!Process32First(hSnapshot, &lppe))
		return 0;

	while (Process32Next(hSnapshot, &lppe)) { // For each process ...
		if (!strcmp(lppe.szExeFile, processName)) { // ... if one is processName ...
			CloseHandle(hSnapshot);
			return lppe.th32ProcessID; // ... we return its PID
		}
	}

	CloseHandle(hSnapshot);

	return 0;
}
