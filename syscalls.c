#include <stdio.h>
#include <windows.h>
#include <ntdef.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_SUPERSEDE 0x00000000
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

typedef struct IO_STATUS_BLOCK{
    union{
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS (NTAPI* ntCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI* rtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef void (NTAPI* initializeObjectAttributes)(
    POBJECT_ATTRIBUTES p,
    PUNICODE_STRING n,
    ULONG a,
    HANDLE r,
    PSECURITY_DESCRIPTOR s
);

PVOID RVAtoRawOffset(UINT_PTR RVA, PIMAGE_SECTION_HEADER section){
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

int main(int argc, char const *argv[]){
    
    //lets get our functions
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    rtlInitUnicodeString RtlInitUnicodeString = (rtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    //1. Read ntdll.dll file bytes from the disk (before any AV/EDR has a chance to hook its functions) 
    HANDLE hFile;
    hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        0,
        NULL,
        3,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if(!hFile){
        printf("[!] Error opening ntdll.dll: %d\n", GetLastError());
        return -1;
    }
    LARGE_INTEGER fileSize;
    if(!GetFileSizeEx(hFile, &fileSize)
    ){
        printf("[!] Error getting filesize: %d\n", GetLastError());
        return -1;
    }
    PBYTE lpFileBuffer = malloc(sizeof(BYTE) * (fileSize.QuadPart + 1));
    DWORD bytesRead = 0;
    if(!ReadFile(
        hFile, 
        lpFileBuffer, 
        fileSize.LowPart, 
        &bytesRead, 
        NULL)
    ){
        printf("[!] Error reading file: %d\n");
        return -1;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)lpFileBuffer + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

    //2. Parse out .rdata and  .text sections of the ntdll.dll file
    size_t numSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);
    PIMAGE_SECTION_HEADER textSection = section; //always first
    PIMAGE_SECTION_HEADER rdataSection;

    for(size_t i = 0; i < numSections; i++){
        if(strcmp((CHAR*)section->Name, (CHAR*)(".rdata"))){
            rdataSection = section;
            break;
        }
        section++;
    }
    
    // .rdata contains ntdll exported function names
    // .text contains code that gets executed by those functions
    DWORD exportDirRVA = pOpHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((UINT_PTR)(lpFileBuffer + exportDirRVA),  rdataSection);
    //3. Locate the specified function's code (syscall) and 
    //  extract the stub (23 bytes) of the NtCreateFile and write it to some memory location
    char syscall[23];
    PDWORD nameAddresses = (PDWORD)RVAtoRawOffset((UINT_PTR)lpFileBuffer + *(&pExportDir->AddressOfNames), rdataSection);
    PDWORD functionAddresses = (PDWORD)RVAtoRawOffset((UINT_PTR)lpFileBuffer + *(&pExportDir->AddressOfFunctions), textSection);
    for(size_t i = 0; i < pExportDir->NumberOfNames; i++){
        UINT_PTR nameVA = (UINT_PTR)RVAtoRawOffset((UINT_PTR)lpFileBuffer + nameAddresses[i], rdataSection);
        UINT_PTR functionVA = (UINT_PTR)RVAtoRawOffset((UINT_PTR)lpFileBuffer + functionAddresses[i + 1], textSection);
        if(strcmp((LPCSTR)nameVA, "NtCreateFile")){
            memcpy(syscall, (LPVOID)functionVA, 23);
            break;
        }
    }

    //5. Define a variable v1 of function type NtCreateFile and point it to the memory location 
    //  where the syscall stub for NtCreateFile is written, as mentioned in step 4.
    //ntCreateFile NtCreateFile = (ntCreateFile)syscall;
    
    //first just testing with this
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    ntCreateFile NtCreateFile = (ntCreateFile)GetProcAddress(ntdll, "NtCreateFile");


    //6. Invoke the NtCreateFile syscall by calling the syscall
    NTSTATUS status;
    HANDLE hCreatedFile = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING filename;
    RtlInitUnicodeString(
        &filename, 
        (LPWSTR)L"FILEPATH HERE"
    );
    InitializeObjectAttributes(
        &oa,
        &filename,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );
    IO_STATUS_BLOCK iosb;
    status = NtCreateFile(
        &hCreatedFile,
        FILE_GENERIC_WRITE,
        &oa,
        &iosb,
        0,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_SUPERSEDE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if(!NT_SUCCESS(status)){
        printf("Failed to create file: %x\n", status);
    }
    free(lpFileBuffer);
    CloseHandle(hFile);
    return 0;
}