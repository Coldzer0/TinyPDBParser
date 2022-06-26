//
// Created by Coldzer0 on 2022/6/22
// Copyright (c) 2022.
//

#include "Core/PDBParser.h"
#include "Core/PEx86.h"
#include <Urlmon.h>
#include <iostream>

namespace fs = std::filesystem;

std::string GetSystem32Dir() {
  std::wstring wide = std::wstring((wchar_t *) 0x7FFE0030);
  wide.append(L"\\system32\\");
  return {wide.begin(), wide.end()};
}

bool DownloadPDB(const std::string &PDBUrl, const std::string &FilePath) {
  HRESULT hr = URLDownloadToFileA(nullptr, PDBUrl.c_str(), FilePath.c_str(), BINDF_GETNEWESTVERSION, nullptr);
  return hr == S_OK;
}

int main(int argc, char **argv) {
  std::string FilePath;
  
  if (argc >= 2)
    FilePath = std::string(argv[1]);
  else
    FilePath = GetSystem32Dir().append("ntoskrnl.exe");
  
  printf("File Path : %s\n", FilePath.c_str());
  std::string PDBUrl = PE::GetPDB_URL_FromPE(FilePath);
  std::string PDBFile = fs::path(PDBUrl).filename().string();
  
  printf("PDB URL  : %s \n", PDBUrl.c_str());
  printf("PDB Name : %s \n\n", PDBFile.c_str());
  
  if (!fs::exists(PDBFile)) {
    printf("PDB Not Found - Downloading the PDB ...\n");
    
    if (DownloadPDB(PDBUrl, PDBFile)) {
      printf("PDB Downloaded\n\n");
    }
  }
  // Check if the file downloaded of not.
  if (fs::exists(PDBFile)) {
    PDBParser::UserSymbols.insert("MmPteBase");
    PDBParser::UserSymbols.insert("MiState");
    PDBParser::UserSymbols.insert("PsSetLoadImageNotifyRoutine");
    PDBParser::UserSymbols.insert("CmRegisterCallbackEx");
    PDBParser::UserSymbols.insert("ObRegisterCallbacks");
    PDBParser::UserSymbols.insert("PsSetCreate"); // Any Symbol contains "PsSetCreate".
    PDBParser::LoadAndCheckSym(FilePath, PDBFile);// Load the PDB file and Parse it using Imagehlp APIs.
  }
  
  system("pause");
  return 0;
}
