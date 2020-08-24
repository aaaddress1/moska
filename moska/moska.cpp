#include <iostream>
#include <Windows.h>

#include "./keystone/keystone.h"
#pragma comment(lib, "keystone.lib")
#pragma warning(disable:4996)
#define file_align 0x200
#define sect_align 0x1000

char* readText(const char* filename)
{
	FILE* fileptr;
	char* buffer;
	printf("[+] income assembly script: %s\n", filename);
	fileptr = fopen(filename, "r");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	size_t filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (char*)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file

	return buffer;
}


#define P2ALIGNUP(size, align) ( ( ((size)/align) + 1) * (align) )
void compilePE(char* shellcode, size_t shellcodeLen,const char* outputName) {


	size_t peHeaderSize = P2ALIGNUP(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), file_align);
	size_t sectionDataSize = P2ALIGNUP(shellcodeLen, 1);
	char* peData = (char*)calloc(peHeaderSize + sectionDataSize, 1);

	// DOS
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE;
	dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	// NT
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew);
	ntHdr->Signature = IMAGE_NT_SIGNATURE;
	ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
	ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	ntHdr->FileHeader.NumberOfSections = 1;

	// Section
	PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char*)ntHdr + sizeof(IMAGE_NT_HEADERS));
	memcpy(&(sectHdr->Name), "30cm.tw", 8);
	sectHdr->VirtualAddress = 0x1000;
	sectHdr->SizeOfRawData = shellcodeLen;
	sectHdr->PointerToRawData = peHeaderSize;
	memcpy(peData + peHeaderSize, shellcode, shellcodeLen);
	sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;

	// Optional Header (config for loader) 
	size_t entryRVA = sectHdr->VirtualAddress;
	ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	ntHdr->OptionalHeader.BaseOfCode = entryRVA; // .text RVA
	ntHdr->OptionalHeader.ImageBase = 0x400000;
	ntHdr->OptionalHeader.FileAlignment = file_align;
	ntHdr->OptionalHeader.SectionAlignment = sect_align;
	ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	ntHdr->OptionalHeader.SizeOfImage = P2ALIGNUP(sectHdr->VirtualAddress + sizeof(*sectHdr), sect_align);
	ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize;
	ntHdr->OptionalHeader.MajorSubsystemVersion = 5; 
	ntHdr->OptionalHeader.MinorSubsystemVersion = 1;

	FILE* fp = fopen(outputName, "wb");
	fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);
	printf("[+] pe file generated done.", outputName);
	fclose(fp);
}


char* generateShellcode(char* CODE,size_t &bytecodeLen)
{
	ks_engine* ks; ks_err err; size_t count; char* encode;

	err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
	if (err != KS_ERR_OK) {
		printf("ERROR: failed on ks_open(), quit\n");
		return 0;
	}
	if (ks_asm(ks, CODE, 0x401000, (unsigned char**)&encode, &bytecodeLen, &count) != KS_ERR_OK) {
		printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
			count, ks_errno(ks));
	}
	else {
		size_t i;
		for (i = 0; i < bytecodeLen; i++) printf("%.2x ", encode[i] & 0xff);
		printf("\n\n[+] sizeof(shellcode) = %lu bytes.\n", bytecodeLen, count);
	}
	return encode;
}

int main(int argc, char** argv)
{
	printf(
		"                      _         \n"
		"  _ __ ___   ___  ___| | ____ _ \n"
		" | '_ ` _ \\ / _ \\/ __| |/ / _` |\n"
		" | | | | | | (_) \\__ \\   < (_| |\n"
		" |_| |_| |_|\\___/|___/_|\\_\\__,_|\n"

#ifdef _WIN64
		" moska_x64 v1, by aaaddress1@chroot.org\n --\n"
#else
		" moska_x86 v1, by aaaddress1@chroot.org\n --\n"
#endif // _WIN64_

		);

	if (argc < 2) {
		auto s = std::string(argv[0]);
		const char* p = s.c_str() + (s.find_last_of('\\') < 0 ? 0 : s.find_last_of('\\') + 1);
		printf(" > usage: %s asm.s [opt:output.exe]\n", p);
		return 0;
	}

	size_t bytecodeLen = 0;
	char* bytecode = generateShellcode(readText(argv[1]), bytecodeLen);
	compilePE(bytecode, bytecodeLen, argc > 2 ? argv[2] : "a.exe" );

}
