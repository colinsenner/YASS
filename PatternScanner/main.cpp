// PatternScanner.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRTDBG_MAP_ALLOC
#include <Windows.h>
#include <crtdbg.h>
#include <stdlib.h>

#include <string>

#include "Timer.h"
#include "lib/SigScanner.h"

struct ScanObject {
  const char* name;
  const char* pattern;
};

int main() {
  // Check for memory leaks
  _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

  //SigScanner scanner("ntdll");

  //std::vector<struct ScanObject> testObjects{
  //  { "Anything", "?? ?? ?? ??"},
  //  { "FirstCCByte", "CC"},
  //  { "DbgUserBreakpoint", "CC 90 C3"},
  //  { "KiUserApcDispatcher", "83 3D ?? ?? ?? ?? ?? 74 0E 8B ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF E1 8D"},
  //  { "RtlInitUnicodeString", "57 8B 7C 24 0C 8B 54 24 08 C7 02 00 00 00 00 89 7A 04 0B FF 74 22"},
  //  { "PssNtQuerySnapshot", "8B FF 55 8B EC 56 57 FF"},
  //};

  //Timer allTime("All scans");
  //for (auto& obj : testObjects) {
  //  {
  //    Timer timer;
  //    auto address = scanner.Scan(obj.pattern);
  //    printf("%s: 0x%p\n", obj.name, address);
  //  }
  //}

  // Create a scanner
  const SigScanner scanner("ntdll");

  // Scan - throws if not found
  auto addr = scanner.Scan("83 3D ?? ?? ?? ?? ?? 74 0E 8B ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF E1 8D");
  printf("%p\n", addr);

  //
}
