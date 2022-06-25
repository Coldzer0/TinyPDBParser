//
// Created by Coldzer0 on 2022/6/18
// Copyright (c) 2022.
//

#ifndef TINYPDBPARSER_PEX86_H
#define TINYPDBPARSER_PEX86_H

#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>

namespace PE {
	/*
	 * PDB constants needed for extraction of the PDB Url.
	 */
	const DWORD PDB70 = 0x53445352; // 'SDSR'
	const DWORD PDB20 = 0x3031424e; // '01BN'

// CodeView header
	typedef struct CV_HEADER_ {
		DWORD CvSignature; // NBxx
		LONG Offset;      // Always 0 for NB10
	} CV_HEADER, *PCV_HEADER;

//// CodeView NB10 debug information
//// (used when debug information is stored in a PDB 2.00 file)
	typedef struct CV_INFO_PDB20_ {
		CV_HEADER Header;
		DWORD Signature;       // seconds since 01.01.1970
		DWORD Age;             // an always-incrementing value
		BYTE PdbFileName[1];   // zero terminated string with the name of the PDB file
	} CV_INFO_PDB20, *PCV_INFO_PDB20;

//// CodeView RSDS debug information
//// (used when debug information is stored in a PDB 7.00 file)
	typedef struct CV_INFO_PDB70_ {
		DWORD CvSignature;
		GUID Signature;       // unique identifier
		DWORD Age;            // an always-incrementing value
		BYTE PdbFileName[1];  // zero terminated string with the name of the PDB file
	} CV_INFO_PDB70, *PCV_INFO_PDB70;
	
	std::string GUIDToString(GUID *guid) {
		char guid_string[37]; // 32 hex chars + 4 hyphens + null terminator
		snprintf(
			guid_string, sizeof(guid_string),
			"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
			guid->Data1, guid->Data2, guid->Data3,
			guid->Data4[0], guid->Data4[1], guid->Data4[2],
			guid->Data4[3], guid->Data4[4], guid->Data4[5],
			guid->Data4[6], guid->Data4[7]);
		return guid_string;
	}
	
	template<typename T>
	T GET_NT_HEADERS(PVOID ImageBase) {
		return (T) ((PBYTE) ImageBase + ((PIMAGE_DOS_HEADER) ImageBase)->e_lfanew);
	}
	
	DWORD RVA2Offset(PVOID ImageBase, DWORD RVA) {
		auto Header = GET_NT_HEADERS<PIMAGE_NT_HEADERS>(ImageBase);
		PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Header);
		for (int i = 0; i < Header->FileHeader.NumberOfSections; ++i) {
			if (RVA >= Section->VirtualAddress && RVA < (Section->VirtualAddress + Section->SizeOfRawData))
				return (Section->PointerToRawData + (RVA - Section->VirtualAddress));
			Section++;
		}
		return 0;
	}
	
	template<typename T>
	PIMAGE_DATA_DIRECTORY GET_HEADER_DICTIONARY(PVOID ImageBase, int Idx) {
		auto Header = GET_NT_HEADERS<T>(ImageBase);
		return (PIMAGE_DATA_DIRECTORY) &Header->OptionalHeader.DataDirectory[Idx];
	}
	
	PVOID RVA2VA(PVOID ImageBase, DWORD RVA) {
		return PVOID((PBYTE) ImageBase + RVA);
	}
	
	std::string GetPDB_URL_FromPE(const std::string &FilePath) {
		
		PIMAGE_DATA_DIRECTORY DebugData = nullptr;
		PIMAGE_DEBUG_DIRECTORY DebugEntry = nullptr;
		char *pdbname = nullptr;
		std::string CustomGUID;
		
		if (std::filesystem::exists(FilePath)) {
			
			std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
			DWORD FileSize = file.tellg();
			file.seekg(0, std::ios::beg);
			
			PVOID ModuleBase = malloc(FileSize);
			if (ModuleBase) {
				
				if (file.read((char *) ModuleBase, FileSize)) {
					
					auto NT = GET_NT_HEADERS<PIMAGE_NT_HEADERS>(ModuleBase);
					if ((NT->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) || (NT->FileHeader.Machine == IMAGE_NT_OPTIONAL_HDR32_MAGIC)) {
						DebugData = GET_HEADER_DICTIONARY<PIMAGE_NT_HEADERS32>(ModuleBase, IMAGE_DIRECTORY_ENTRY_DEBUG);
					} else if ((NT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) || (NT->FileHeader.Machine == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
						DebugData = GET_HEADER_DICTIONARY<PIMAGE_NT_HEADERS64>(ModuleBase, IMAGE_DIRECTORY_ENTRY_DEBUG);
					} else {
						printf("File Is not Valid\n");
						DebugData = nullptr;
					}
					
					if (DebugData) {
						DWORD Offset = RVA2Offset(ModuleBase, DebugData->VirtualAddress);
						
						if (Offset) {
							DWORD count = DebugData->Size / sizeof(IMAGE_DEBUG_DIRECTORY);
							DebugEntry = (PIMAGE_DEBUG_DIRECTORY) ((PBYTE) ModuleBase + Offset);
							
							for (int i = 0; i < count; ++i) {
								if (DebugEntry->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
									auto debug = (PVOID) ((PBYTE) ModuleBase + DebugEntry->PointerToRawData);
									DWORD signature = ((PCV_HEADER) debug)->CvSignature;
									
									switch (signature) {
										case PDB70: {
											GUID guid = ((PCV_INFO_PDB70) debug)->Signature;
											DWORD age = ((PCV_INFO_PDB70) debug)->Age;
											pdbname = (char *) ((PCV_INFO_PDB70) debug)->PdbFileName;
											CustomGUID = std::string(pdbname) + "/" + GUIDToString(&guid) + std::to_string(age) + "/" + std::string(pdbname);
											break;
										}
										case PDB20: {
											DWORD timestamp = ((PCV_INFO_PDB20) debug)->Signature;
											DWORD age = ((PCV_INFO_PDB20) debug)->Age;
											pdbname = (char *) ((PCV_INFO_PDB20) debug)->PdbFileName;
											char time_age[10];
											snprintf(time_age, sizeof(time_age), "%08X%x", timestamp, age);
											CustomGUID = std::string(pdbname) + "/" + std::string(time_age) + "/" + std::string(pdbname);
											break;
										}
										default:;
									}
								}
								DebugEntry++;
							}
						}
					}
				}
				free(ModuleBase);
				
				return (!pdbname) ? "" : std::string("http://msdl.microsoft.com/download/symbols/") + CustomGUID;
			} else
				printf("Can't Allocate Memory");
		} else {
			printf("File not found. \n");
		}
		return "";
	}
	
}
#endif //TINYPDBPARSER_PEX86_H
