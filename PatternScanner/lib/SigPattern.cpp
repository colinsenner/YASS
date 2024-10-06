#include "SigPattern.h"

#include <iostream>

SigPattern::SigPattern(const char* pattern) : Bytes(nullptr) {
  Parse(pattern);
}

SigPattern::~SigPattern() {
  delete[] Bytes;
  delete[] Mask;
}

size_t SigPattern::Length() const {
  return _patternLength;
}

bool SigPattern::Match(const uint8_t byte, const size_t pos) const {
  const bool bytesMatch = byte == Bytes[pos];
  const bool byteMustMatch = Mask[pos];

  return bytesMatch || byteMustMatch == false;
}

void SigPattern::Parse(const char* szPattern) {
  std::string pattern = szPattern;

  // Remove all spaces
  const auto end_pos = std::remove(pattern.begin(), pattern.end(), ' ');
  pattern.erase(end_pos, pattern.end());

  _patternLength = pattern.length() / 2;

  Bytes = new uint8_t[_patternLength];
  Mask = new bool[_patternLength];

  // Extract bytes
  size_t pos = 0;
  for (size_t i = 0; i < pattern.length(); i += 2) {
    auto hexStr = pattern.substr(i, 2);

    if (hexStr == "??") {
      // This byte can be any value
      Bytes[pos] = 0;
      Mask[pos] = false;
    } else {
      // Parse the exact value
      const auto val = static_cast<uint8_t>(strtol(hexStr.c_str(), nullptr, 16));

      Bytes[pos] = val;
      Mask[pos] = true;
    }

    pos++;
  }
}
