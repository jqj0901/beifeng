#include "stdafx.h"
#include "APIHOOK.h"
#include "GL/GL.h"



#pragma comment(lib,"OpenGL32.lib")

void WINAPI Myglbegin(GLenum mode);
void(_stdcall *NewglBegin)(GLenum);
DWORD HookSign;
APIHOOK opengl("opengl32.dll");

void inject() {
	/*
	AllocConsole();
	FILE *stream;
	freopen_s(&stream, "CON", "r", stdin);
	freopen_s(&stream, "CON", "w", stdout);
	*/

	//备份opengl32.dll的内存
	DWORD BaseAddress = (DWORD)GetModuleHandleA("opengl32.dll");

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS32 pinh = (PIMAGE_NT_HEADERS32)(BaseAddress + pidh->e_lfanew);
	PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);
	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)(BaseAddress + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD AllocSize = pinh->OptionalHeader.SizeOfImage;
	DWORD NewBaseAddress = (DWORD)VirtualAlloc(0, AllocSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	/*
	printf("opengl32DllBase=%x\n", BaseAddress);
	printf("NewBaseAddress=%x\n", NewBaseAddress);
	*/


	DWORD NowAddress = BaseAddress;
	DWORD pos = NewBaseAddress;
	DWORD old, temp;
	MEMORY_BASIC_INFORMATION meminfo;
	//printf("starting copy...\n");
	while (NowAddress < BaseAddress + pinh->OptionalHeader.SizeOfImage) {
		//copy所有内存块
		if (!VirtualQuery((LPCVOID)NowAddress, &meminfo, 28)) {
			break;
		}

		//printf("copy block BaseAddress=%x Size=%x\n", meminfo.BaseAddress, meminfo.RegionSize);

		VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_EXECUTE_READWRITE, &old);

		memcpy((LPVOID)pos, (LPVOID)NowAddress, meminfo.RegionSize);

		VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, old, &temp);
		NowAddress += meminfo.RegionSize;
		pos += meminfo.RegionSize;
	}
	/*
	printf("copy successfully!\n");
	system("pause");
	printf("start apiname scan... NumberOfNames=%d\n", pied->NumberOfNames);
	*/
	int i;
	for (i = 0; i < pied->NumberOfNames; i++) {
		//printf("%s\n", (const char *)(*(DWORD *)(NewBaseAddress + pied->AddressOfNames + i * 4) + NewBaseAddress));
		if (!strcmp((const char *)(*(DWORD *)(NewBaseAddress + pied->AddressOfNames + i * 4) + NewBaseAddress), "glBegin")) {
			break;
		}
	}

	//printf("scan sccessfully!!,i=%d\n",i);


	WORD xuhao = *(WORD *)(NewBaseAddress + pied->AddressOfNameOrdinals + i * 2);
	NewglBegin = (void(_stdcall*)(GLenum))(*(DWORD *)(xuhao * 4 + NewBaseAddress + pied->AddressOfFunctions) + NewBaseAddress);

	/*
	printf("glBegin=%x\n", GetProcAddress(GetModuleHandleA("opengl32.dll"), "glBegin"));
	printf("MyglBegin=%x\n", &Myglbegin);
	printf("NewglBegin=%x\n", NewglBegin);
	system("pause");
	*/
	//HOOK


	HookSign = opengl.HookApi("glBegin", (DWORD)&Myglbegin);
}

void WINAPI Myglbegin(GLenum mode) {
	if (mode == GL_TRIANGLE_STRIP || mode == GL_TRIANGLE_FAN) {
		glDisable(GL_DEPTH_TEST);
	}
	_asm {
		push mode;
		call NewglBegin
	}


}

void unhook() {
	opengl.RecoveryApi(HookSign);
}