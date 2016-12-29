#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "CProcess.h"


int main() {
	CProcess* Proc = new CProcess(L"DOOMx64vk.exe");

	std::cout << "Acquiring offsets..." << std::endl << "Stand by, this may take a few seconds..." << std::endl;

	//Example of using signatures
	uintptr_t AMMO_Addr = Proc->FindPatternEx("\x01\x51\x38\x8B\x71\x38", "xxxxxx");
	uintptr_t ResScale_Offset = Proc->FindPatternExOffset("\x89\x01\xF3\x0F\x10\x05\x8F\x80\x48\xEA\x0F\x57\xC9\x0F\x2F\xC1\x76\x09", "xxxxxx????xxxxxxxx", 4, 6, true, 7);

	std::vector<float> ResScale(2);

	ReadProcessMemory(Proc->Process, (void*)(Proc->ProcBase + ResScale_Offset), &ResScale[0], sizeof(float), NULL);
	ReadProcessMemory(Proc->Process, (void*)(Proc->ProcBase + ResScale_Offset + 0x90), &ResScale[1], sizeof(float), NULL);

	std::cout << "Current Res-Scale is: " << ResScale[0] * 100 << "%-X * " << ResScale[1] * 100 << "%-Y" << std::endl;
	Sleep(5000);

	return 0;
}