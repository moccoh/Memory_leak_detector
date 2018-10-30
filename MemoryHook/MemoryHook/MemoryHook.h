#ifndef MEM_HOOK
#define MEM_HOOK
#pragma once

#include <windows.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>

/*
This is the list that keept all memory leak until the end
*/
#pragma region MEM_INFO and MEM_LEAK

struct _MEM_INFO // We have here the Memory Leak struct and infos
{
	void			*address;
	unsigned int	size;
	char			file_name[256];
	char			func[50];
	unsigned int	line;
};
typedef struct _MEM_INFO MEM_INFO;

struct _MEM_LEAK {	//List of Memory Leak
	MEM_INFO mem_info;
	struct _MEM_LEAK * next;
};
typedef struct _MEM_LEAK MEM_LEAK;

static MEM_LEAK * ptr_start = NULL; // pointer to the first node of the list
static MEM_LEAK * ptr_next = NULL;
#pragma endregion

#pragma region IAT prototype
LPVOID GetIATProcAddress(LPCSTR);

bool ChangeIATAdress(char * function, DWORD OldProtect, DWORD* AdressIAT);
#pragma endregion

#pragma region functions add,delete,clear prototype
void add(MEM_INFO alloc_info);
void erase(unsigned pos);
void clear(void);

void add_mem_info(void * mem_ref, unsigned int size, const char * file, unsigned int line, char * func);
void remove_mem_info(void * mem_ref);

#pragma endregion 

#pragma region Prototype and declarations of functions

#pragma region Hook Malloc Prototype

typedef LPVOID(WINAPIV *MallocFunc)(size_t); // Prototype of malloc
LPVOID WINAPIV HookMalloc(size_t size); //Declaration of the hooked function
LPVOID originalMalloc; //Adress of the real malloc

typedef LPVOID(WINAPI *HeapAllocFunc)(HANDLE, DWORD, size_t);
LPVOID WINAPI HookHeapAlloc(HANDLE Heap, DWORD dwflags, size_t size);
LPVOID originalHeapAlloc;


#pragma endregion

#pragma region Hook Calloc Prototype

typedef LPVOID(WINAPIV *CallocFunc)(size_t, size_t);
LPVOID WINAPIV HookCalloc(size_t count, size_t size);
LPVOID originalCalloc;

#pragma endregion

#pragma region Hook free Prototype

typedef void(WINAPIV *FreeFunc)(LPVOID);
void WINAPIV HookFree(LPVOID adress);
LPVOID originalFree;

typedef BOOL(WINAPI *HeapFreeFunc)(HANDLE, DWORD, LPVOID);
BOOL WINAPI HookHeapFree(HANDLE &Heap, DWORD dwflags, LPVOID Ipmem);
LPVOID originalHeapFree;

typedef void(WINAPIV *_free_dbgFunc)(LPVOID, int);
void WINAPIV Hook_free_dbg(LPVOID adress, int bloc);
LPVOID original_free_dbg;

#pragma endregion

#pragma region Hook Realloc Prototype

typedef LPVOID(WINAPIV *ReallocFunc)(LPVOID, size_t);
LPVOID WINAPIV HookRealloc(LPVOID adress, size_t size);
LPVOID originalRealloc;

#pragma endregion

#pragma endregion

#pragma region stack frames
unsigned long hash;
const int Frametocapture = 64;
void * backtrace[Frametocapture];

const int MAXSYMBOLNAME = 128 - sizeof(PIMAGEHLP_SYMBOL64);
char symbol64_buf[sizeof(PIMAGEHLP_SYMBOL64) + MAXSYMBOLNAME] = { 0 };
PIMAGEHLP_SYMBOL64 symbol = reinterpret_cast<PIMAGEHLP_SYMBOL64 >(symbol64_buf);
IMAGEHLP_LINE64 lineSymbol = { 0 };
DWORD displacement;
HANDLE process;
#pragma endregion

void returnInformations(int &line, char *&func, char* &filename); //return this informations from the stack frame
#endif
