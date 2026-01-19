#include <windows.h>
#include <stdio.h>
template <typename T>
T GetNTHeader(LPVOID base)
{
	return (T)((PBYTE)base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
}
BOOL CheckPESignatures(LPVOID base)
{
	PIMAGE_DOS_HEADER dheader = (PIMAGE_DOS_HEADER)base;
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
		if (RVA >= Section->VirtualAddress && RVA < (Section->VirtualAddress + Section->SizeOfRawData))
			return (Section->PointerToRawData + (RVA - Section->VirtualAddress));
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
	auto NT = GetNTHeader<PIMAGE_NT_HEADERS>(base);
	PIMAGE_DATA_DIRECTORY importdatadir;
	if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		importdatadir = GetDataDirectory<PIMAGE_NT_HEADERS64>(base, IMAGE_DIRECTORY_ENTRY_IMPORT);
	}
	else if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
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
		if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			ProcessThunks<PIMAGE_THUNK_DATA64>(base, oftoff);
		}
		else if (NT->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 || NT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			ProcessThunks<PIMAGE_THUNK_DATA32>(base, oftoff);
		}
		// TODO: Implement API sets parsing

	}
}