#pragma once
#include <stdlib.h>

#include <memory>
#include <string>
#include <vector>

class SigPattern {
 public:
  SigPattern(const char*);
  ~SigPattern();

  size_t Length() const;

  bool Match(uint8_t byte, size_t pos) const;

  uint8_t* Bytes;
  bool* Mask;

 private:
  void Parse(const char* str);

  size_t _patternLength;
};
