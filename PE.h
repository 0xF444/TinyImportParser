#pragma once
#include <windows.h>
#include <stdio.h>
#define IMAGE_IS_x64 0
#define IMAGE_IS_x86 1
#define rva2raw(a, o) ((a) - (o))
#define raw2rva(a, o) ((a) + (o))
template <typename T>
T GetNTHeader(LPVOID base)
{
	return (T)((PBYTE)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
}
int CheckPEBitness(LPVOID base) {
	auto NT = GetNTHeader<PIMAGE_NT_HEADERS>(base);
	if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return IMAGE_IS_x64;
	}
	else if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		return IMAGE_IS_x86;
	}
}
BOOL CheckPESignatures(LPVOID base)
{
	auto dheader = (PIMAGE_DOS_HEADER)base;
	if (dheader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		auto ntheader = GetNTHeader<PIMAGE_NT_HEADERS>(base);
		if (ntheader->Signature == IMAGE_NT_SIGNATURE)
		{
			return 1;
		}
		return 0;
	}
	return 0;
}
DWORD RVA2Offset(PVOID ImageBase, DWORD RVA) {
	auto Header = GetNTHeader<PIMAGE_NT_HEADERS>(ImageBase);
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Header);
	for (int i = 0; i < Header->FileHeader.NumberOfSections; ++i) {
		DWORD end = Section->VirtualAddress + Section->SizeOfRawData;
		if (RVA >= Section->VirtualAddress && RVA < end) {
			DWORD delta = rva2raw(RVA, Section->VirtualAddress);
			return Section->PointerToRawData + delta;
		}
		Section++;
	}
	return 0;
}
template <typename T>
PIMAGE_DATA_DIRECTORY GetDataDirectory(LPVOID base, DWORD indx)
{
	auto NT = GetNTHeader<T>(base);
	return (PIMAGE_DATA_DIRECTORY)&NT->OptionalHeader.DataDirectory[indx];
}
template <typename T>
void ProcessThunks(PVOID base, DWORD oftoff) {
	auto thunkdata = (T)((PBYTE)base + oftoff);

	while (thunkdata->u1.Function != 0) {
		if (!IMAGE_SNAP_BY_ORDINAL(thunkdata->u1.Function)) {
			DWORD nameRVA = (DWORD)(thunkdata->u1.Function);
			PIMAGE_IMPORT_BY_NAME importbyname = (PIMAGE_IMPORT_BY_NAME)((PBYTE)base + RVA2Offset(base, nameRVA));

			printf("\t%s\n", importbyname->Name);
		}
		thunkdata++;
	}
}