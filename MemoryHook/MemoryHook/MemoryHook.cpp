#include <windows.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include "dbghelp.h"
#include "MemoryHook.h"
#include <mutex>

std::mutex m, l, p, r;

/*
* When we load or unload a DLL, this function is called by the process.
*/
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID)
{
	if (dwReason == DLL_PROCESS_ATTACH)  //When the library is load in the process
	{
		// This part is the initialisation for the caputureStackBacktrace
		process = GetCurrentProcess();
		symbol->SizeOfStruct = sizeof(PIMAGEHLP_SYMBOL64);
		symbol->MaxNameLength = MAXSYMBOLNAME - 1;
		lineSymbol.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
		SymInitialize(process, NULL, TRUE);


		MessageBox(NULL, L"Hook.dll has been injected !", L"Hook.dll", 0);
		DWORD OldProtect = NULL;
		DWORD* AdressIAT = NULL;
		
		// If there is a bug in changement of the IAT (and if not, changement in IAT done for all the functions)
		if ((ChangeIATAdress("malloc", OldProtect, AdressIAT) || (ChangeIATAdress("realloc", OldProtect, AdressIAT)) || (ChangeIATAdress("_free_dbg", OldProtect, AdressIAT))  || (ChangeIATAdress("calloc", OldProtect, AdressIAT)) || (ChangeIATAdress("free", OldProtect, AdressIAT))))
		{
			MessageBox(NULL, L"Hook not work", L"Hook.dll", 0);
			return TRUE;
		}
	}

	if (dwReason == DLL_PROCESS_DETACH) //When the library is Unload in the process
	{
		MessageBox(NULL, L"PROCESSDETACHED", L"Hook.dll", 0);

		MEM_LEAK * leak_info; //pointer for the "list" of Memory Leak

		FILE * fp_write;
		errno_t err;

		if (ptr_start == NULL && (err = fopen_s(&fp_write, "leak_info.txt", "w+")) == 0) // if ptrstart = NULL so no Memory Leak
			fprintf(fp_write, "No Memory Leak \n");
		else
		{
			if ((err = fopen_s(&fp_write, "leak_info.txt", "w+")) == 0)
			{
				for (leak_info = ptr_start; leak_info != NULL; leak_info = leak_info->next)  //We go trough the list and write in the file all the memory leaks
				{
					fprintf(fp_write, "Memory Leak \n");
					fprintf(fp_write, "-----------------------------------\n");
					fprintf(fp_write, "address : %d\n", leak_info->mem_info.address);
					fprintf(fp_write, "size    : %d bytes\n", leak_info->mem_info.size);
					fprintf(fp_write, "file name: %s\n", leak_info->mem_info.file_name);
					fprintf(fp_write, "function: %s\n", leak_info->mem_info.func);
					fprintf(fp_write, "line : %d\n", leak_info->mem_info.line);
					fprintf(fp_write, "-----------------------------------\n");
				}
			}
		}
	}

	return TRUE;
}

#pragma region IAT
/*
* Hook is here, simply change the adress of the function in IAT, by mine.
*/
bool ChangeIATAdress(char * function, DWORD OldProtect, DWORD* AdressIAT)
{
	AdressIAT = (DWORD*)GetIATProcAddress(function); //AdressIAT will equal to the adress of function in IAT

	if (AdressIAT != NULL) // if the function found in IAT
	{
		//modify the autorization of this adress to write in and keep the oldProtect
		if (!VirtualProtect(AdressIAT, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &OldProtect))
			return TRUE;
		if (function == "malloc")
		{
			originalMalloc = (LPVOID)*AdressIAT;//keep it aside
			*AdressIAT = (DWORD)&HookMalloc;//change the adress with the adress of my Function (THE HOOK IS HERE)
		}
		else if (function == "calloc")
		{
			originalCalloc = (LPVOID)*AdressIAT;
			*AdressIAT = (DWORD)&HookCalloc;
		}
		else if (function == "free")
		{
			originalFree = (LPVOID)*AdressIAT;
			*AdressIAT = (DWORD)&HookFree;
		}
		else if (function == "realloc")
		{
			originalRealloc = (LPVOID)*AdressIAT;
			*AdressIAT = (DWORD)&HookRealloc;
		}
		else if (function == "_free_dbg")
		{
			original_free_dbg = (LPVOID)*AdressIAT;
			*AdressIAT = (DWORD)&Hook_free_dbg;
		}
		VirtualProtect(AdressIAT, sizeof(LPVOID), OldProtect, &OldProtect); //Old rights returned
	}
	return FALSE;
}

/*
* This function is use to search in the header of the PE (in the IAT), the adress of the function we need (FunctionName).
*/
LPVOID GetIATProcAddress(LPCSTR FunctionName)
{
	HANDLE hProcess = GetModuleHandle(NULL);
	if (!hProcess)
		return NULL;
	PIMAGE_DOS_HEADER pPE = (PIMAGE_DOS_HEADER)hProcess;
	if (pPE->e_magic != IMAGE_DOS_SIGNATURE) // MZ Signature
		return NULL;

	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pPE->e_lfanew + (DWORD)pPE);

	LPVOID pImageDirectory =
		(LPVOID)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageDirectory
		+ (DWORD)pPE);

	while (*(LPDWORD)pImageImportDescriptor != 0)
	{
		PIMAGE_THUNK_DATA pHintNameArray = (PIMAGE_THUNK_DATA)(pImageImportDescriptor->OriginalFirstThunk
			+ (DWORD)pPE);
		PIMAGE_THUNK_DATA pImportAddressTable = (PIMAGE_THUNK_DATA)(pImageImportDescriptor->FirstThunk +
			(DWORD)pPE);

		while (*(LPDWORD)pHintNameArray != 0)
		{
			PIMAGE_IMPORT_BY_NAME pImageName = (PIMAGE_IMPORT_BY_NAME)(pHintNameArray->u1.AddressOfData +
				(DWORD)pPE);
			if (!strcmp((char*)&pImageName->Name, FunctionName))
			{
				return &(pImportAddressTable->u1.Function);
			}

			pHintNameArray++;
			pImportAddressTable++;
		}

		pImageImportDescriptor++;
	}
	return NULL;
}
#pragma endregion

#pragma region Hook Functions
/*
* All these functions are the "diverted" function, they return the "return" of the real function.
*/
LPVOID WINAPIV HookMalloc(size_t size)  // function new call malloc
{
	std::lock_guard<std::mutex> lk(m);

	int line;
	char *func;
	char * file;
	returnInformations(line, func, file);
	LPVOID ptr = ((MallocFunc)originalMalloc)(size); // call the original malloc
	if (ptr != NULL)
	{
		add_mem_info(ptr, size, file, line, func); // add this malloc to the list
	}
	return ptr;
}

void WINAPIV HookFree(LPVOID adress)
{
	std::lock_guard<std::mutex> lk(l);

	remove_mem_info(adress);
	((FreeFunc)originalFree)(adress);
}

void WINAPIV Hook_free_dbg(LPVOID adress, int bloc) //delete call _free_dbg
{
	std::lock_guard<std::mutex> lk(l);
	MessageBox(NULL, L"HOOK_free_dbg CALLED", L"Hook.dll", 0);
	remove_mem_info(adress);
	((_free_dbgFunc)original_free_dbg)(adress, bloc);
}

LPVOID WINAPIV HookCalloc(size_t count, size_t size)
{
	std::lock_guard<std::mutex> lk(p);

	int line;
	char *func;
	char * file;
	returnInformations(line, func, file);
	printf("LA %s\n", func);
	unsigned total_size;
	LPVOID ptr = ((CallocFunc)originalCalloc)(count, size);
	if (ptr != NULL)
	{
		total_size = count * size;
		add_mem_info(ptr, total_size, file, line, func);
	}
	return ptr;
}

LPVOID WINAPIV HookRealloc(LPVOID adress, size_t size)
{
	std::lock_guard<std::mutex> lk(r);


	int line;
	char *func;
	char * file;
	returnInformations(line, func, file);

	LPVOID ptr = ((ReallocFunc)originalRealloc)(adress, size);
	if (ptr != NULL)
		add_mem_info(ptr, size, file, line, func);
	remove_mem_info(adress);
	return ptr;
	
}

#pragma region Heap not work
//LPVOID WINAPI HookHeapAlloc(HANDLE Heap, DWORD dwflags, size_t size,  int line,  char* file)  //not working
//{
//
//	MessageBox(NULL, L"HOOK HEAPALLOC CALLED", L"Hook.dll", 0);
//	LPVOID ptr = ((HeapAllocFunc)originalHeapAlloc)(Heap, dwflags, size);
//	if (ptr != NULL)
//	{
//		add_mem_info(ptr, size, file, line);
//	}
//	return ptr;
//}
//
//BOOL WINAPI HookHeapFree(HANDLE &Heap, DWORD dwflags, LPVOID Ipmem, const int line, const char* file) //not working
//{
//	MessageBox(NULL, L"HOOK ALLOCFree CALLED", L"Hook.dll", 0);
//	remove_mem_info(Ipmem);
//	return ((HeapFreeFunc)originalHeapFree)(&Heap, dwflags, Ipmem);
//}
#pragma endregion

#pragma endregion

void returnInformations(int &line, char *&func, char* &filename)
{
	CaptureStackBackTrace(0, Frametocapture, backtrace, &hash); //capture the 64 stack frame before this function (sf of this function include)

	bool a = SymGetSymFromAddr64(process, (DWORD64)backtrace[2], 0, symbol);//get a Stack frame ,here the backtrace[1], because the 0 is the stack frame of our function (HookMalloc) so 1 return the stack frame of the function caller
	func = symbol->Name;
	a = SymGetLineFromAddr64(process, (DWORD64)backtrace[2], &displacement, &lineSymbol);
	line = lineSymbol.LineNumber;
	filename = lineSymbol.FileName;


	char * temp = func;
	if (!strcmp(temp, "operator new"))     // case if its the operator new function, the stack frame is not the 1.
	{
		a = SymGetSymFromAddr64(process, (DWORD64)backtrace[4], 0, symbol);
		func = symbol->Name;
		a = SymGetLineFromAddr64(process, (DWORD64)backtrace[4], &displacement, &lineSymbol);
		line = lineSymbol.LineNumber;
		filename = lineSymbol.FileName;
	}
}

#pragma region functions add,delete,clear

/*
* adds allocated memory info. into the list
*
*/
void add(MEM_INFO alloc_info)
{

	MEM_LEAK * mem_leak_info = NULL;
	mem_leak_info = (MEM_LEAK *)malloc(sizeof(MEM_LEAK));
	mem_leak_info->mem_info.address = alloc_info.address;
	mem_leak_info->mem_info.size = alloc_info.size;
	strcpy_s(mem_leak_info->mem_info.file_name, sizeof mem_leak_info->mem_info.file_name, alloc_info.file_name);
	strcpy_s(mem_leak_info->mem_info.func, sizeof mem_leak_info->mem_info.func, alloc_info.func);
	mem_leak_info->mem_info.line = alloc_info.line;
	mem_leak_info->next = NULL;

	if (ptr_start == NULL)
	{
		ptr_start = mem_leak_info;
		ptr_next = ptr_start;
	}
	else {
		ptr_next->next = mem_leak_info;
		ptr_next = ptr_next->next;
	}

}

/*
* erases memory info. from the list
*
*/
void erase(unsigned pos)
{

	unsigned index = 0;
	MEM_LEAK * alloc_info, *temp;

	if (pos == 0)
	{
		MEM_LEAK * temp = ptr_start;
		ptr_start = ptr_start->next;
		free(temp);
	}
	else
	{
		for (index = 0, alloc_info = ptr_start; index < pos;
		alloc_info = alloc_info->next, ++index)
		{
			if (pos == index + 1)
			{
				temp = alloc_info->next;
				alloc_info->next = temp->next;
				free(temp);
				break;
			}
		}
	}
}

/*
* deletes all the elements from the list
*/
void clear()
{
	MEM_LEAK * temp = ptr_start;
	MEM_LEAK * alloc_info = ptr_start;

	while (alloc_info != NULL)
	{
		alloc_info = alloc_info->next;
		free(temp);
		temp = alloc_info;
	}
}

void add_mem_info(void * mem_ref, unsigned int size, const char * file, unsigned int line, char* func)
{
	MEM_INFO mem_alloc_info;

	/* fill up the structure with all info */
	memset(&mem_alloc_info, 0, sizeof(mem_alloc_info));
	mem_alloc_info.address = mem_ref;
	mem_alloc_info.size = size;
	strncpy_s(mem_alloc_info.file_name, sizeof mem_alloc_info.file_name, file, 256);
	strncpy_s(mem_alloc_info.func, sizeof mem_alloc_info.func, func, 50);
	mem_alloc_info.line = line;

	/* add the above info to a list */
	add(mem_alloc_info);
}

void remove_mem_info(void * mem_ref)
{
	unsigned short index;
	MEM_LEAK  * leak_info = ptr_start;

	/* check if allocate memory is in our list */
	for (index = 0; leak_info != NULL; ++index, leak_info = leak_info->next)
	{
		if (leak_info->mem_info.address == mem_ref)
		{
			erase(index);
			break;
		}
	}
}

#pragma endregion