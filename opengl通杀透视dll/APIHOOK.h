#pragma once

#ifndef _APIHOOK_
#define _APIHOOK_

#include "windows.h"
#include "vector"
#include "string"

using namespace std;

void ChangeSectionReadWrite(DWORD BaseAddress,PIMAGE_SECTION_HEADER pish) {
	DWORD temp;
	VirtualProtect((LPVOID)(pish->VirtualAddress + BaseAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &temp);
}
PIMAGE_SECTION_HEADER GetRvaSection(PIMAGE_NT_HEADERS32 pinh, DWORD Rva) {
	PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);

	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		if (Rva >= pish[i].VirtualAddress && Rva < (pish[i].VirtualAddress + pish[i].Misc.VirtualSize)) {
			return pish + i;
		}
	}
	return NULL;
}

DWORD _declspec(naked) _stdcall CallApi(DWORD jmpadd, int argcount, DWORD *argpointer) {

	_asm {
		push ebp;
		mov ebp, esp;
		sub esp, 0xc;
		mov ecx, argcount;
		mov esi, argpointer;
	loop1:
		dec ecx;
		push[esi + ecx * 4];
		
		jne loop1;

		call start;
		add esp,0xc;
		pop ebp;
		ret 0xc;
	start:
		mov eax, jmpadd;
		push ebp;
		mov ebp, esp;
		jmp eax;

	}

}

DWORD CallNextApi(DWORD HookSign, int argcount, ...) {
	va_list args;
	va_start(args, argcount);
	DWORD *value = new DWORD[argcount];
	for (int i = 0; i < argcount; i++) {
		value[i] = va_arg(args, DWORD);

	}
	DWORD ret= CallApi(HookSign + 5, argcount, value);
	delete[] value;
	return ret;
}

class IATHOOK {
public:
	IATHOOK(const char *ModuleName) {
		
		DllName = ModuleName;
		BaseAddress= (DWORD)GetModuleHandle(NULL);
		pidh = (PIMAGE_DOS_HEADER)BaseAddress;
		pinh = (PIMAGE_NT_HEADERS32)(BaseAddress + pidh->e_lfanew);
		piid = (PIMAGE_IMPORT_DESCRIPTOR)(BaseAddress + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		pish = IMAGE_FIRST_SECTION(pinh);
		tosmall((char *)DllName.data());
	}
	bool HookApi(const char *ApiName, DWORD NewAddress) {
		if (pinh->Signature != 'EP') {
			return false;
		}
		DWORD *ApiPointer;
		if ((ApiPointer = GetApiAddressPointer(ApiName)) == NULL) {
			return false;
		}
		ChangeSectionReadWrite(BaseAddress,GetRvaSection(pinh,(DWORD)((DWORD)ApiPointer-BaseAddress)));
		
		this->Hooks.push_back({std::string(ApiName),ApiPointer, *ApiPointer });
		memcpy(ApiPointer, &NewAddress, 4);
		return true;

	}
	bool RecoveryApi(const char *ApiName) {
	
		vector<struct Hookinfo>::iterator iter=Hooks.begin();
		for (int i = 0; iter != Hooks.end();i++) {
			if (iter[i].ApiName== ApiName) {
				memcpy(iter[i].AddressPointer, &iter[i].oldaddress, 4);
				Hooks.erase(iter);
				return true;
			}
		}
		return false;
	}
	~IATHOOK() {
		;
	}
	DWORD *GetApiAddressPointer(const char *ApiName){

		unsigned int i, j;
		DWORD ThunkValue;
		std::string Name;
		
		for (i = 0; piid[i].FirstThunk != 0; i++) {
			Name.clear();
			Name = (const char *)(BaseAddress + piid[i].Name);
			
			tosmall((char *)Name.data());
			if (Name==DllName) {
				for (j = 0; (ThunkValue = *(DWORD *)(BaseAddress + piid[i].OriginalFirstThunk + j)) != 0; j += 4) {
					if (ThunkValue & 0x80000000) { continue; }
					if (!strcmp(ApiName, (const char *)(BaseAddress + ThunkValue+2))) {
						
						return (DWORD *)(BaseAddress + piid[i].FirstThunk + j);
					}
				}
			}
			
		}
		return NULL;
	}
private:
	struct Hookinfo {
		std::string ApiName;
		DWORD *AddressPointer;
		DWORD oldaddress;

	};
	std::string DllName;
	DWORD BaseAddress;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS32 pinh;
	PIMAGE_IMPORT_DESCRIPTOR piid;
	PIMAGE_SECTION_HEADER pish;
	vector <Hookinfo>Hooks;
	void tosmall(char *str) {
		for (int i = 0; str[i] != 0; i++) {
			str[i] |= 32;
		}
	}
	
};
class APIHOOK {
public:
	APIHOOK(const char *ModuleName) {
		DllName = ModuleName;
		DllBase = (DWORD)GetModuleHandleA(ModuleName);
		pidh = (PIMAGE_DOS_HEADER)DllBase;
		pinh = (PIMAGE_NT_HEADERS32)(DllBase + pidh->e_lfanew);
	}
	//返回一个Hook标识
	DWORD HookApi(const char *ApiName,DWORD NewAddress) {
		//成功则返回Hook标识
		string Name;
		Name = ApiName;
		DWORD ApiBaseAddress = (DWORD)GetProcAddress((HMODULE)DllBase, ApiName);
		if (ApiBaseAddress == 0) { return 0; }
		struct Hookinfo info;
		info.ApiName = Name;
		memcpy(&info.oldbytes, (LPVOID)ApiBaseAddress, 5);
		info.HookSign = ApiBaseAddress;
		Hooks.push_back(info);
		unsigned char NewByte[5];
		NewByte[0] = 0xE9;
		ApiBaseAddress += 5;
		NewAddress -= ApiBaseAddress;
		ApiBaseAddress -= 5;
		memcpy(NewByte + 1, &NewAddress, 4);
		ChangeSectionReadWrite(DllBase, GetRvaSection(pinh, ApiBaseAddress - DllBase));
		memcpy((LPVOID)ApiBaseAddress, NewByte, 5);

		

		return ApiBaseAddress;
	}
	bool RecoveryApi(DWORD HookSign) {
	
		vector<Hookinfo>::iterator iter = Hooks.begin();
		for (int i = 0; iter != Hooks.end(); i++) {
			if (iter[i].HookSign == HookSign) {
				memcpy((LPVOID)iter[i].HookSign, &iter[i].oldbytes, 5);
				Hooks.erase(iter);
				return true;
			}
		}
		return false;
	}
	

	

private:
	
	struct Hookinfo {
		unsigned char oldbytes[5];
		string ApiName;
		DWORD HookSign;
	};
	vector<Hookinfo> Hooks;
	string DllName;
	DWORD DllBase;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
};


#endif
