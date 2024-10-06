#pragma once
#include <Windows.h>
#include <stdlib.h>

#include <vector>

class SigScanner {
 public:
  SigScanner(const char* moduleName);

  SigScanner(const SigScanner&) = delete;
  SigScanner& operator=(const SigScanner&) = delete;

  void* Scan(const char* pattern) const;

 private:
  void GetTextSectionBytes(HMODULE hModule);

  HMODULE _hModule = nullptr;
  uint8_t* _textSectionVA = nullptr;
  size_t _textSectionSize = 0;
};
