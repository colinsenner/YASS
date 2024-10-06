#include "SigScanner.h"

#include <DbgHelp.h>
#include <Windows.h>
#include <stdlib.h>

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "SigPattern.h"

#pragma comment(lib, "dbghelp.lib")

SigScanner::SigScanner(const char *moduleName) {
  _hModule = GetModuleHandleA(moduleName);

  if (_hModule == nullptr) {
    printf("Module '%s' not found.", moduleName);
    throw std::runtime_error("Module not found");
  }

  GetTextSectionBytes(_hModule);
}

void *SigScanner::Scan(const char *szPattern) const {
  const SigPattern pattern = szPattern;

  uint8_t *codeStart = _textSectionVA;
  const uint8_t *codeEnd = _textSectionVA + _textSectionSize;

  for (uint8_t *pAddress = codeStart; pAddress < codeEnd; pAddress++) {
    uint8_t module_byte = *pAddress;

    if (pattern.Match(module_byte, 0)) {
      // The module byte matches the first byte in our pattern
      // Check the entire pattern now, starting with the second byte

      // Edge case where our pattern is just one byte
      if (pattern.Length() == 1) {
        return pAddress;
      }

      for (size_t j = 1; j < pattern.Length(); j++) {
        module_byte = *(pAddress + j);

        // If anything doesn't match, restart
        if (!pattern.Match(module_byte, j)) {
          break;
        }

        // If everything has matched and we're at the end of the pattern, we've found it
        if (j == pattern.Length() - 1) {
          return pAddress;
        }
      }
    }
  }

  throw std::runtime_error("Couldn't find pattern " + std::string(szPattern));
}

PIMAGE_SECTION_HEADER GetPESection(const HANDLE hModule, const char *sectionName) {
  // get the location of the module's IMAGE_NT_HEADERS structure
  IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(hModule);

  // section table immediately follows the IMAGE_NT_HEADERS
  auto pSectionHdr = reinterpret_cast<IMAGE_SECTION_HEADER*>(pNtHdr + 1);

  char scnName[sizeof(pSectionHdr->Name) + 1];
  scnName[sizeof(scnName) - 1] =
      '\0';  // enforce nul-termination for scn names that are the whole length of pSectionHdr->Name[]

  for (int scn = 0; scn < pNtHdr->FileHeader.NumberOfSections; ++scn) {
    // Note: pSectionHdr->Name[] is 8 bytes long. If the scn name is 8 bytes long, ->Name[] will
    // not be nul-terminated. For this reason, copy it to a local buffer that's nul-terminated
    // to be sure we only print the real scn name, and no extra garbage beyond it.
    strncpy_s(scnName, reinterpret_cast<const char*>(pSectionHdr->Name), sizeof(pSectionHdr->Name));

    if (!_strcmpi(scnName, sectionName)) {
      return pSectionHdr;
    }
    ++pSectionHdr;
  }

  return nullptr;
}

void SigScanner::GetTextSectionBytes(HMODULE hModule) {
  auto section = GetPESection(hModule, ".text");

  _textSectionVA = static_cast<uint8_t *>((uint8_t *)hModule + section->VirtualAddress);
  _textSectionSize = section->Misc.VirtualSize;

  return;
}
