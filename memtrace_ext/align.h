// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef ALIGN_H_
#define ALIGN_H_

#include <cstddef>
#include <cstdint>

namespace {  // NOLINT(build/namespaces_headers)

template <size_t N>
struct Int;

template <>
struct Int<4> {
  using U = std::uint32_t;
};

template <>
struct Int<8> {
  using U = std::uint64_t;
};

template <typename T>
T GetAligned(T pos, size_t n) {
  using U = typename Int<sizeof(T)>::U;
  U uPos = (U)pos;
  U aligned = (uPos + static_cast<U>(n - 1)) & ~static_cast<U>(n - 1);
  return (T)aligned;
}

}  // namespace

#endif  // ALIGN_H_
