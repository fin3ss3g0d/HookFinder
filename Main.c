/* 
    Author: Dylan Evans (fin3ss3g0d)
    Credits: https://github.com/trickster0
*/

#pragma once
#include <Windows.h>
#include "Structs.h"
#include <stdio.h>

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
    _In_ PVOID                     pModuleBase,
    _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
int HookFinder(
    _In_ PVOID pModuleBase,
    _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory
);

INT wmain() {

    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;

    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x01;

    printf("************ BEGIN HOOK DETECTION ************\n");
    HookFinder(pLdrDataEntry->DllBase, pImageExportDirectory);

    return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

int HookFinder(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (strncmp(pczFunctionName, "Nt", strlen("Nt")) == 0 || strncmp(pczFunctionName, "Zw", strlen("Zw")) == 0) {
            
            char* st;
            st = strstr(pczFunctionName, "QuerySystemTime");
            if (st) {
                continue;
            }
            else if (*((PBYTE)pFunctionAddress) == 0xe9) {
                printf("[+] %s is hooked with JMP at first byte!\n", pczFunctionName);
            }
            else if (*((PBYTE)pFunctionAddress + 3) == 0xe9) {
                printf("[+] %s is hooked with JMP at third byte!\n", pczFunctionName);
            }
            else {
                printf("[*] No hooks detetcted for %s!\n", pczFunctionName);
            }
        }
    }

    return 0;
}