//
// Created by Coldzer0 on 2022/6/22
// Copyright (c) 2022.
//

#ifndef TINYPDBPARSER_PDBPARSER_H
#define TINYPDBPARSER_PDBPARSER_H

#include <windows.h>
#include <filesystem>
#include <imagehlp.h>
#include <set>

namespace fs = std::filesystem;

namespace PDBParser {
  
  std::set<std::string> UserSymbols;
  
  WINBOOL EnumSymCallBack(PSYMBOL_INFO pSymInfo, [[maybe_unused]] ULONG SymbolSize, [[maybe_unused]] PVOID UserContext) {
    if (pSymInfo->NameLen == 0)
      return true;
    
    for (const std::string &Sym: UserSymbols) {
      if (std::string(pSymInfo->Name).find(Sym) == 0) {
        printf("Name    : %s   \n", pSymInfo->Name);
        printf("Base    : 0x%x \n", pSymInfo->ModBase);
        printf("Address : 0x%x \n", pSymInfo->Address);
        printf("Offset  : 0x%x \n", (pSymInfo->Address - pSymInfo->ModBase));
        printf("============================\n");
      }
    }
    
    return true;
  }
  
  bool LoadAndCheckSym(const std::string &FilePath, const std::string &PDBName) {
    
    /**
   * Don't Use -1 as Current Handle.
   * Ref:
   * https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize#parameters
   */
    HANDLE CurrentHandle = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
    if (CurrentHandle != INVALID_HANDLE_VALUE) {
      bool SymbolsPathInit = SymInitialize(CurrentHandle, fs::current_path().string().c_str(), false);
      if (SymbolsPathInit) {
        SymSetOptions(SymGetOptions() | SYMOPT_CASE_INSENSITIVE | SYMOPT_LOAD_ANYTHING);
        SymSetSearchPath(CurrentHandle, fs::current_path().string().c_str());
        
        SIZE_T SymBase = SymLoadModule(CurrentHandle, nullptr, FilePath.c_str(), nullptr, 0, 0);
        if (SymBase != 0) {
          return SymEnumSymbols(CurrentHandle, SymBase, nullptr, EnumSymCallBack, nullptr);
        }
      }
    }
    return false;
  }
  
}// namespace PDBParser

#endif// TINYPDBPARSER_PDBPARSER_H
