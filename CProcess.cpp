#include <string>
#include <vector>

#include "CProcess.h"


CProcess::CProcess(std::wstring ProcName) {
	this->Module = ProcName;

	this->GetProcID(ProcName);
	this->GetProcModule(ProcName);
	this->Process = OpenProcess(PROCESS_ALL_ACCESS, false, this->ProcID);
}


bool CProcess::GetProcID(std::wstring ProcName) {


	PROCESSENTRY32 ProcEntry = { NULL };
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (!Snap) { return NULL; }

	ProcEntry.dwSize = sizeof(ProcEntry);

	if (!Process32First(Snap, &ProcEntry)) { return NULL; }

	do {
		if (!wcscmp(ProcEntry.szExeFile, ProcName.c_str())) {
			CloseHandle(Snap);
			this->ProcID = ProcEntry.th32ProcessID;
			return false;
		}
	} while (Process32Next(Snap, &ProcEntry));

	CloseHandle(Snap);
	return true;
}

void CProcess::GetProcModule(std::wstring ModuleName) {

	MODULEENTRY32 ModEntryTMP = { 0 };
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcID);

	if (Snap != INVALID_HANDLE_VALUE) {
		ModEntryTMP.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(Snap, &ModEntryTMP)) {
			do {
				if (!wcscmp(ModEntryTMP.szModule, ModuleName.c_str())) { break; }
			} while (Module32Next(Snap, &ModEntryTMP));
		}
		CloseHandle(Snap);
	}
	this->ModEntry = ModEntryTMP;
	this->ProcBase = (uintptr_t)ModEntryTMP.modBaseAddr;
}

DWORD CProcess::GetDwordFromBytes(byte *B, bool LittleEndian)
{
	if (!LittleEndian) { return (B[3]) | (B[2] << 8) | (B[1] << 16) | (B[0] << 24); }
	else { return (B[0]) | (B[1] << 8) | (B[2] << 16) | (B[3] << 24); }
}


uintptr_t CProcess::FindPattern(byte* Base, size_t Size, std::string Pattern, std::string Mask) {

	size_t patternLength = Mask.length();

	for (uintptr_t i = 0; i < Size - patternLength; i++) {
		bool found = true;
		for (uintptr_t j = 0; j < patternLength; j++) {
			if (Mask[j] != '?' && Pattern[j] != *(char*)(Base + i + j)) {
				found = false;
				break;
			}
		}

		if (found) { return (uintptr_t)Base + i; }
	}
	return 0;
}

//Returns Address of the Signature
uintptr_t CProcess::FindPatternEx(std::string Pattern, std::string Mask) {

	uintptr_t Start = (uintptr_t)this->ModEntry.modBaseAddr;
	uintptr_t End = Start + this->ModEntry.modBaseSize;
	uintptr_t Chunk = Start;
	SIZE_T BytesRead;

	while (Chunk < End) {
		std::vector<BYTE> Buffer(4096);

		ReadProcessMemory(this->Process, (void*)Chunk, &Buffer.front(), 4096, &BytesRead);

		if (BytesRead == 0) { return 0; }

		uintptr_t InternalAddress = FindPattern(&Buffer.front(), BytesRead, Pattern, Mask);

		if (InternalAddress != 0) {
			uintptr_t Offset = InternalAddress - (uintptr_t)&Buffer.front();
			return Chunk + Offset;
		}

		else { Chunk += BytesRead; }
	}

	return 0;
}

//Returns an offset found at the address at the signature
uintptr_t CProcess::FindPatternExOffset(std::string Pattern, std::string Mask, size_t Size, size_t Offset, bool LittleEndian, size_t Instsize) {
	std::vector<BYTE> Data;
	Data.resize(Size);

	uintptr_t Address = FindPatternEx(Pattern, Mask);

	ReadProcessMemory(this->Process, (void*)(Address + Offset), &Data.front(), Size, NULL);
	Address += Offset - (Instsize - Size);

	return Address + Instsize + (uintptr_t)GetDwordFromBytes(&Data.front(), LittleEndian) - (uintptr_t)this->ModEntry.modBaseAddr;
}