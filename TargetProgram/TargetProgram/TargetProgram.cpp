#include <Windows.h>
#include <stdio.h>


DWORD WINAPI func(int a)
{
	printf("func done \n");
	int * ptr1 = (int *)malloc(a);
	return 1;
}

int main(int argc, char *argv[])
{
	Sleep(6000); // time to try inject when already run

	DWORD dwThreadID = 0;
	HANDLE ha = NULL;

	ha = CreateThread(
		NULL,              // default security
		50,                 // default stack size
		(LPTHREAD_START_ROUTINE)func,        // name of the thread function
		(LPVOID)5,              // no thread parameters
		0,                 // default startup flags
		&dwThreadID);

	func(5);

	int * ptr1 = (int *)malloc(10);
	printf("%s \n", "malloc done");

	int * ptra(0);
	ptra = new int[15];
	printf("%s \n", "new done");

	int * ptr4 = (int *)calloc(2, 4);
	printf("%s \n", "calloc done");

	char * ptrb = (char *)malloc(5);

	int *ptr5 = (int *)realloc(ptr4, 30);
	printf("%s \n ", "calloc done");

	free(ptr1);

	WaitForSingleObject(ha, INFINITE);
	system("pause");
	return 0;
}


