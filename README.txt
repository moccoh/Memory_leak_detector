Memory Leak Detector

To detect memory leaks,
the program must know all dynamic allocations as well as their release that have been made on the target program. 
The aim of the project was to detect memory leaks in c programs,
but it’s also work for c++. (dependent on the compiler, see on limits).
To do this, we will hook functions such as malloc or free and redirect them to our functions,
which will record the different calls before returning the result of the real function.
The technique used here is the IAT hooking with Dll injection.
So the program will contain a Dll with the hooked functions, an injector to inject the Dll into the target, 
and a target example program.

3 parts in this project:

- DLL_injector: the injector of the dll, into the Debug, i have already put the dll and the target program, you have
just to drag and drop the target into the injector. (or use cmd) Possibility to Inject into a running programm:

>Dll_Inject.exe target.exe 1

In my target program there is a Sleep function in the beggining to have time th do the injection.

- MemoryHook: the big part of this project, it's the dll with the IAT hook.

- Target Program: i think i put there all the possibilty like malloc calloc, with function, without function, with thread etc...

Example of Output:

Memory Leak 
-----------------------------------
address : 9465432
size    : 5 bytes
file name: c:\users\moche\desktop\memory leak detector\targetprogram\targetprogram\targetprogram.cpp
function: func
line : 8
-----------------------------------
Memory Leak 
-----------------------------------
address : 9465544
size    : 10 bytes
file name: c:\users\moche\desktop\memory leak detector\targetprogram\targetprogram\targetprogram.cpp
function: main
line : 28


Moché Cohen.