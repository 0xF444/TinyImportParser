#include <stdio.h>
#include <windows.h>
#include "PE.h"
int main(int argc, char** argv) {
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (argc < 2) {
		printf("Usage: TinyImportParser.exe <image_file>\n");
		return -1;
	}
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("An error has occurred: %x\n", GetLastError());
		return -1;
	}
	DWORD HighSize;
	DWORD MAXSIZE = GetFileSize(hFile, &HighSize);
	LPVOID base = malloc(MAXSIZE + HighSize);
	if (!base) {
		printf("Error allocating memory, aborting!\n");
		return -1;
	}
	memset(base, 0, MAXSIZE);
	BOOL isRead = ReadFile(hFile, base, MAXSIZE + HighSize, NULL, NULL);
	if (!isRead)
	{
		printf("Error reading file: %x\n", GetLastError());
		return -1;
	}
	if (!CheckPESignatures(base))
	{
		printf("Error: %s is not a valid PE file.", argv[1]);
		return -1;
	}

	PIMAGE_DATA_DIRECTORY importdatadir;
	if (CheckPEBitness(base) == IMAGE_IS_x64)
	{
		importdatadir = GetDataDirectory<PIMAGE_NT_HEADERS64>(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
	}
	else if (CheckPEBitness(base) == IMAGE_IS_x86)
	{
		importdatadir = GetDataDirectory<PIMAGE_NT_HEADERS32>(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
	}
	else
	{
		printf("File is not compiled on Intel based processors, aborting!\n");
		return -1;
	}
	auto importdesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)base + RVA2Offset(base, importdatadir->VirtualAddress)); // This gives a correct fileoffset.
	for (auto i = importdesc; i->Characteristics != 0; i++)
	{
		DWORD offset = RVA2Offset(base, i->Name);
		PBYTE dllname = (PBYTE)base + offset;
		printf("DLL Import: %s\n", dllname);
		DWORD oftoff = RVA2Offset(base, i->OriginalFirstThunk);
		if (CheckPEBitness(base) == IMAGE_IS_x64)
		{
			ProcessThunks<PIMAGE_THUNK_DATA64>(base, oftoff);
		}
		else if (CheckPEBitness(base) == IMAGE_IS_x86)
		{
			ProcessThunks<PIMAGE_THUNK_DATA32>(base, oftoff);
		}
		// TODO: Implement API sets parsing

	}
}