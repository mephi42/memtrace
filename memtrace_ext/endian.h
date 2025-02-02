// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef ENDIAN_H_
#define ENDIAN_H_

#include <cstdint>

namespace {  // NOLINT(build/namespaces_headers)

enum class Endianness {
  Little,
  Big,
};

const char* GetStr(Endianness endianness) {
  switch (endianness) {
    case Endianness::Little:
      return "Little";
    case Endianness::Big:
      return "Big";
    default:
      return nullptr;
  }
}

const char* GetEndiannessStrPy(Endianness endianness) {
  switch (endianness) {
    case Endianness::Little:
      return "<";
    case Endianness::Big:
      return ">";
    default:
      return nullptr;
  }
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
constexpr Endianness kHostEndianness = Endianness::Little;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
constexpr Endianness kHostEndianness = Endianness::Big;
#else
#error Unsupported __BYTE_ORDER__
#endif

std::uint8_t BSwap(std::uint8_t value) { return value; }

std::uint16_t BSwap(std::uint16_t value) { return __builtin_bswap16(value); }

std::uint32_t BSwap(std::uint32_t value) { return __builtin_bswap32(value); }

std::uint64_t BSwap(std::uint64_t value) { return __builtin_bswap64(value); }

template <Endianness, typename T>
struct IntConversions {
  static T ConvertToHost(T value) { return BSwap(value); }
};

template <typename T>
struct IntConversions<kHostEndianness, T> {
  static T ConvertToHost(T value) { return value; }
};

}  // namespace

#endif  // ENDIAN_H_
