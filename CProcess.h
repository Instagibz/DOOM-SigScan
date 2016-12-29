#pragma once
#include <windows.h>
#include <TlHelp32.h>

class CProcess {


public:
	CProcess::CProcess(std::wstring ProcName);

	HANDLE Process;
	MODULEENTRY32 ModEntry;
	DWORD ProcID;
	std::wstring Module;
	uintptr_t ProcBase;

	bool CProcess::GetProcID(std::wstring ProcName);
	void CProcess::GetProcModule(std::wstring ModuleName);
	DWORD CProcess::GetDwordFromBytes(byte *B, bool LittleEndian);
	uintptr_t CProcess::FindPattern(byte* Base, size_t Size, std::string Pattern, std::string Mask);
	uintptr_t CProcess::FindPatternEx(std::string Pattern, std::string Mask);
	uintptr_t CProcess::FindPatternExOffset(std::string Pattern, std::string Mask, size_t Size, size_t Offset, bool LittleEndian, size_t Instsize);


};
