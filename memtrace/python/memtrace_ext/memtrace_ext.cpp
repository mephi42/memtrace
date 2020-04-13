// Copyright (C) 2019-2020, and GNU GPL'd, by mephi42.
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

// clang-format off
#include <boost/python.hpp>
#include <boost/python/object/iterator_core.hpp>
#include <boost/python/scope.hpp>
#include <boost/python/suite/indexing/map_indexing_suite.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
#include <capstone/capstone.h>  // NOLINT(build/include_order)
// clang-format on

namespace {

enum class Tag {
  MT_LOAD = 0x4c4c,
  MT_STORE = 0x5353,
  MT_REG = 0x5252,
  MT_INSN = 0x4949,
  MT_GET_REG = 0x4747,
  MT_PUT_REG = 0x5050,
  MT_INSN_EXEC = 0x5858,
  MT_GET_REG_NX = 0x6767,
  MT_PUT_REG_NX = 0x7070,
  MT_MMAP = 0x4d4d,
};

const char* GetTagStr(Tag tag) {
  switch (tag) {
    case Tag::MT_LOAD:
      return "MT_LOAD";
    case Tag::MT_STORE:
      return "MT_STORE";
    case Tag::MT_REG:
      return "MT_REG";
    case Tag::MT_INSN:
      return "MT_INSN";
    case Tag::MT_GET_REG:
      return "MT_GET_REG";
    case Tag::MT_PUT_REG:
      return "MT_PUT_REG";
    case Tag::MT_INSN_EXEC:
      return "MT_INSN_EXEC";
    case Tag::MT_GET_REG_NX:
      return "MT_GET_REG_NX";
    case Tag::MT_PUT_REG_NX:
      return "MT_PUT_REG_NX";
    case Tag::MT_MMAP:
      return "MT_MMAP";
    default:
      return nullptr;
  }
}

enum class MachineType {
  EM_386 = 3,
  EM_X86_64 = 62,
  EM_PPC = 20,
  EM_PPC64 = 21,
  EM_ARM = 40,
  EM_AARCH64 = 183,
  EM_S390 = 22,
  EM_MIPS = 8,
  EM_NANOMIPS = 249,
};

const char* GetMachineTypeStr(MachineType type) {
  switch (type) {
    case MachineType::EM_386:
      return "EM_386";
    case MachineType::EM_X86_64:
      return "EM_X86_64";
    case MachineType::EM_PPC:
      return "EM_PPC";
    case MachineType::EM_PPC64:
      return "EM_PPC64";
    case MachineType::EM_ARM:
      return "EM_ARM";
    case MachineType::EM_AARCH64:
      return "EM_AARCH64";
    case MachineType::EM_S390:
      return "EM_S390";
    case MachineType::EM_MIPS:
      return "EM_MIPS";
    case MachineType::EM_NANOMIPS:
      return "EM_NANOMIPS";
    default:
      return nullptr;
  }
}

enum class Endianness {
  Little,
  Big,
};

const char* GetEndiannessStr(Endianness endianness) {
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

class Overlay {
 public:
  explicit Overlay(const std::uint8_t* data) : data_(data) {}
  const uint8_t* GetData() const { return data_; }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename T, typename B = Overlay>
class RawInt : public B {
 public:
  using B::B;

  T GetValue() const {
    return IntConversions<E, T>::ConvertToHost(
        *reinterpret_cast<const T*>(this->GetData()));
  }
};

template <Endianness E, typename W, typename B = Overlay>
class Tlv : public B {
 public:
  using B::B;

  static constexpr size_t kFixedLength = sizeof(std::uint16_t) * 2;

  Tag GetTag() const {
    return static_cast<Tag>(
        RawInt<E, std::uint16_t>(this->GetData()).GetValue());
  }
  W GetLength() const {
    return RawInt<E, std::uint16_t>(this->GetData() + 2).GetValue();
  }
  W GetAlignedLength() const {
    return (GetLength() + (static_cast<W>(sizeof(W)) - 1)) &
           ~(static_cast<W>(sizeof(W)) - 1);
  }
};

template <Endianness E, typename W, typename B = Overlay>
class HeaderEntry : public B {
 public:
  using B::B;

  static constexpr size_t kFixedLength =
      Tlv<E, W>::kFixedLength + sizeof(std::uint16_t);

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  MachineType GetMachineType() const {
    return static_cast<MachineType>(
        RawInt<E, std::uint16_t>(this->GetData() + kMachineTypeOffset)
            .GetValue());
  }
  std::uint16_t GetRegsSize() const {
    return RawInt<E, std::uint16_t>(this->GetData() + kRegsSizeOffset)
        .GetValue();
  }

 private:
  static constexpr size_t kMachineTypeOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kRegsSizeOffset =
      kMachineTypeOffset + sizeof(std::uint16_t);
};

template <Endianness E, typename W, typename B = Overlay>
class LdStEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  std::uint32_t GetInsnSeq() const {
    return RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset)
        .GetValue();
  }
  W GetAddr() const {
    return RawInt<E, W>(this->GetData() + kAddrOffset).GetValue();
  }
  const std::uint8_t* GetValue() const {
    return this->GetData() + kValueOffset;
  }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(kValueOffset);
  }
  std::vector<std::uint8_t> CopyValue() const {
    return std::vector<std::uint8_t>(GetValue(), GetValue() + GetSize());
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kAddrOffset = kInsnSeqOffset + sizeof(std::uint32_t);
  static constexpr size_t kValueOffset = kAddrOffset + sizeof(W);
};

template <Endianness E, typename W, typename B = Overlay>
class InsnEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  std::uint32_t GetInsnSeq() const {
    return RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset)
        .GetValue();
  }
  W GetPc() const {
    return RawInt<E, W>(this->GetData() + kPcOffset).GetValue();
  }
  const std::uint8_t* GetValue() const {
    return this->GetData() + kValueOffset;
  }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(kValueOffset);
  }
  std::vector<std::uint8_t> CopyValue() const {
    return std::vector<std::uint8_t>(GetValue(), GetValue() + GetSize());
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kPcOffset = kInsnSeqOffset + sizeof(std::uint32_t);
  static constexpr size_t kValueOffset = kPcOffset + sizeof(W);
};

template <Endianness E, typename W, typename B = Overlay>
class InsnExecEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  std::uint32_t GetInsnSeq() const {
    return RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset)
        .GetValue();
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
};

template <Endianness E, typename W, typename B = Overlay>
class LdStNxEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  std::uint32_t GetInsnSeq() const {
    return RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset)
        .GetValue();
  }
  W GetAddr() const {
    return RawInt<E, W>(this->GetData() + kAddrOffset).GetValue();
  }
  W GetSize() const {
    return RawInt<E, W>(this->GetData() + kSizeOffset).GetValue();
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kAddrOffset = kInsnSeqOffset + sizeof(std::uint32_t);
  static constexpr size_t kSizeOffset = kAddrOffset + sizeof(W);
};

template <Endianness E, typename W, typename B = Overlay>
class MmapEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  W GetStart() const {
    return RawInt<E, W>(this->GetData() + kStartOffset).GetValue();
  }
  W GetEnd() const {
    return RawInt<E, W>(this->GetData() + kEndOffset).GetValue();
  }
  W GetFlags() const {
    return RawInt<E, W>(this->GetData() + kFlagsOffset).GetValue();
  }
  std::uint64_t GetOffset() const {
    return RawInt<E, std::uint64_t>(this->GetData() + kOffsetOffset).GetValue();
  }
  std::uint64_t GetDev() const {
    return RawInt<E, std::uint64_t>(this->GetData() + kDevOffset).GetValue();
  }
  std::uint64_t GetInode() const {
    return RawInt<E, std::uint64_t>(this->GetData() + kInodeOffset).GetValue();
  }
  const std::uint8_t* GetValue() const {
    return this->GetData() + kValueOffset;
  }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(kValueOffset);
  }
  std::string CopyValue() const {
    return reinterpret_cast<const char*>(GetValue());
  }

 private:
  // Not Tlv<E, W>::kFixedLength due to padding.
  static constexpr size_t kStartOffset = sizeof(W);
  static constexpr size_t kEndOffset = kStartOffset + sizeof(W);
  static constexpr size_t kFlagsOffset = kEndOffset + sizeof(W);
  static constexpr size_t kOffsetOffset = kFlagsOffset + sizeof(W);
  static constexpr size_t kDevOffset = kOffsetOffset + sizeof(std::uint64_t);
  static constexpr size_t kInodeOffset = kDevOffset + sizeof(std::uint64_t);
  static constexpr size_t kValueOffset = kInodeOffset + sizeof(std::uint64_t);
};

void HexDump(std::FILE* f, const std::uint8_t* buf, size_t n) {
  for (size_t i = 0; i < n; i++) std::fprintf(f, "%02x", buf[i]);
}

void ReprDump(const std::uint8_t* buf, size_t n) {
  std::printf("b'");
  for (size_t i = 0; i < n; i++) std::printf("\\x%02x", buf[i]);
  std::printf("'");
}

template <Endianness E>
void ValueDump(const std::uint8_t* buf, size_t n) {
  switch (n) {
    case 1:
      std::printf("0x%" PRIx8, RawInt<E, std::uint8_t>(buf).GetValue());
      break;
    case 2:
      std::printf("0x%" PRIx16, RawInt<E, std::uint16_t>(buf).GetValue());
      break;
    case 4:
      std::printf("0x%" PRIx32, RawInt<E, std::uint32_t>(buf).GetValue());
      break;
    case 8:
      std::printf("0x%" PRIx64, RawInt<E, std::uint64_t>(buf).GetValue());
      break;
    default:
      ReprDump(buf, n);
      break;
  }
}

void HtmlDump(std::FILE* f, const char* s) {
  std::string escaped;
  for (; *s; s++) {
    switch (*s) {
      case '"':
        escaped += "&quot;";
        break;
      case '&':
        escaped += "&amp;";
        break;
      case '\'':
        escaped += "&#39;";
        break;
      case '<':
        escaped += "&lt;";
        break;
      case '>':
        escaped += "&gt;";
        break;
      default:
        escaped += *s;
        break;
    }
  }
  std::fprintf(f, "%s", escaped.c_str());
}

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

ssize_t ReadN(int fd, void* buf, size_t count) {
  size_t totalSize = 0;
  while (count != 0) {
    ssize_t chunkSize = read(fd, buf, count);
    if (chunkSize < 0) return chunkSize;
    if (chunkSize == 0) {
      errno = EINVAL;
      break;
    }
    buf = static_cast<char*>(buf) + chunkSize;
    count -= chunkSize;
    totalSize += chunkSize;
  }
  return totalSize;
}

enum class InitMode {
  CreateTemporary,
  CreatePersistent,
  OpenExisting,
};

template <typename T>
class MmVector {
 public:
  using iterator = T*;
  using const_iterator = const T*;
  using reference = T&;
  using const_reference = const T&;

  MmVector() : fd_(-1), storage_(nullptr), capacity_(0) {}
  template <typename U>
  MmVector(const MmVector<U>&) = delete;
  ~MmVector() {
    if (storage_ != nullptr) {
      if (ftruncate(fd_, kOverhead + storage_->size * sizeof(T)) == 0)
        capacity_ = storage_->size;
      munmap(storage_, kOverhead + capacity_ * sizeof(T));
    }
    close(fd_);
  }

  [[nodiscard]] int Init(const char* path, InitMode mode) {
    switch (mode) {
      case InitMode::CreateTemporary: {
        size_t len = strlen(path);
        std::unique_ptr<char[]> tempPath(new char[len + 7]);
        memcpy(&tempPath[0], path, len);
        memset(&tempPath[len], 'X', 6);
        tempPath[len + 6] = '\0';
        fd_ = mkstemp(tempPath.get());
        if (fd_ == -1) return -errno;
        unlink(tempPath.get());
        return InitCreated();
      }
      case InitMode::CreatePersistent:
        fd_ = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd_ == -1) return -errno;
        return InitCreated();
      case InitMode::OpenExisting:
        fd_ = open(path, O_RDWR);
        if (fd_ == -1) return -errno;
        return InitOpened();
      default:
        return -EINVAL;
    }
  }

  [[nodiscard]] int InitCreated() {
    if (ftruncate(fd_, kOverhead) == -1) return -errno;
    void* newStorage =
        mmap(nullptr, kOverhead, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (newStorage == MAP_FAILED) return -errno;
    storage_ = static_cast<Storage*>(newStorage);
    storage_->size = 0;
    return 0;
  }

  [[nodiscard]] int InitOpened() {
    Storage header;
    if (ReadN(fd_, &header, kOverhead) != kOverhead) return -errno;
    void* newStorage = mmap(nullptr, kOverhead + header.size * sizeof(T),
                            PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (newStorage == MAP_FAILED) return -errno;
    storage_ = static_cast<Storage*>(newStorage);
    capacity_ = storage_->size;
    return 0;
  }

  bool IsInitalized() const { return storage_ != nullptr; }

  T* data() { return storage_->entries; }
  const T* data() const { return storage_->entries; }
  size_t size() const { return storage_->size; }
  size_t capacity() const { return capacity_; }
  iterator begin() { return storage_->entries; }
  const_iterator begin() const { return storage_->entries; }
  iterator end() { return &storage_->entries[storage_->size]; }
  const_iterator end() const { return &storage_->entries[storage_->size]; }
  reference front() { return storage_->entries[0]; }
  const_reference front() const { return storage_->entries[0]; }
  reference back() { return storage_->entries[storage_->size - 1]; }
  const_reference back() const { return storage_->entries[storage_->size - 1]; }
  reference operator[](size_t n) { return storage_->entries[n]; }
  const_reference operator[](size_t n) const { return storage_->entries[n]; }

  void reserve(size_t n) {
    if (n <= capacity_) return;
    if (ftruncate(fd_, kOverhead + n * sizeof(T)) == -1) throw std::bad_alloc();
    void* newStorage = mremap(storage_, kOverhead + capacity_ * sizeof(T),
                              kOverhead + n * sizeof(T), MREMAP_MAYMOVE);
    if (newStorage == MAP_FAILED) throw std::bad_alloc();
    storage_ = static_cast<Storage*>(newStorage);
    capacity_ = n;
  }

  void push_back(const T& val) {
    if (storage_->size + 1 > capacity_) Grow();
    storage_->entries[storage_->size++] = val;
  }

  template <typename... Args>
  reference emplace_back(Args&&... args) {
    if (storage_->size + 1 > capacity_) Grow();
    new (&storage_->entries[storage_->size]) T(std::forward(args)...);
    return storage_->entries[storage_->size++];
  }

  template <typename InputIterator>
  void insert(iterator position, InputIterator first, InputIterator last) {
    size_t i = position - &storage_->entries[0];
    size_t n = last - first;
    if (i + n > capacity_) {
      Grow(GetAligned((i + n - capacity_) * sizeof(T), kGrowAmount));
      position = &storage_->entries[i];
    }
    InputIterator input = first;
    iterator end = &storage_->entries[storage_->size];
    while (position != end && input != last) *(position++) = *(input++);
    while (input != last) new (position++) T(*(input++));
    storage_->size = std::max(storage_->size, n + i);
  }

  void resize(size_t n, T val = T()) {
    if (n > capacity_)
      Grow(GetAligned((n - capacity_) * sizeof(T), kGrowAmount));
    for (size_t i = storage_->size; i < n; i++)
      new (&storage_->entries[i]) T(val);
    storage_->size = n;
  }

 private:
  static constexpr size_t kGrowAmount = 1024 * 1024 * 1024;

  void Grow(size_t bytes = kGrowAmount) {
    reserve(capacity_ + bytes / sizeof(T));
  }

  int fd_;
  struct Storage {
    size_t size;
    T entries[1];  // C++ has no FAM!
  };
  static constexpr size_t kOverhead = sizeof(Storage) - sizeof(T);
  Storage* storage_;
  size_t capacity_;
};

class CsFree {
 public:
  explicit CsFree(size_t count) : count_(count) {}

  void operator()(cs_insn* insn) { cs_free(insn, count_); }

 private:
  const size_t count_;
};

class Disasm {
 public:
  Disasm() : capstone_(0) {}
  ~Disasm() {
    if (capstone_ != 0) cs_close(&capstone_);
  }

  int Init(MachineType type, Endianness endianness, size_t wordSize) {
    // See cstool.c for valid combinations.
    cs_arch arch;
    cs_mode mode;
    switch (type) {
      case MachineType::EM_386:
        if (endianness != Endianness::Little || wordSize != 4) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
        break;
      case MachineType::EM_X86_64:
        if (endianness != Endianness::Little || wordSize != 8) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
        break;
        // EM_PPC is not supported.
      case MachineType::EM_PPC64:
        if (wordSize != 8) return -EINVAL;
        arch = CS_ARCH_PPC;
        if (endianness == Endianness::Little)
          mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
        else
          mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::EM_ARM:
        if (wordSize != 4) return -EINVAL;
        arch = CS_ARCH_ARM;
        if (endianness == Endianness::Little)
          mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
        else
          mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::EM_AARCH64:
        if (wordSize != 8) return -EINVAL;
        arch = CS_ARCH_ARM64;
        if (endianness == Endianness::Little)
          mode = CS_MODE_LITTLE_ENDIAN;
        else
          mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::EM_S390:
        if (endianness != Endianness::Big) return -EINVAL;
        arch = CS_ARCH_SYSZ;
        mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::EM_MIPS:
        arch = CS_ARCH_MIPS;
        if (wordSize == 4) {
          if (endianness == Endianness::Little)
            mode = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
          else
            mode = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN);
        } else {
          if (endianness == Endianness::Little)
            mode = static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN);
          else
            mode = static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN);
        }
        break;
        // EM_NANOMIPS is not supported.
      default:
        return -1;
    }
    if (cs_open(arch, mode, &capstone_) != CS_ERR_OK) return -1;
    return 0;
  }

  std::unique_ptr<cs_insn, CsFree> DoDisasm(const std::uint8_t* code,
                                            size_t codeSize,
                                            std::uint64_t address,
                                            size_t count) const {
    cs_insn* insn = nullptr;
    size_t actualCount =
        cs_disasm(capstone_, code, codeSize, address, count, &insn);
    return std::unique_ptr<cs_insn, CsFree>(insn, CsFree(actualCount));
  }

  std::string DisasmStr(const std::vector<std::uint8_t>& code,
                        std::uint64_t address) {
    std::unique_ptr<cs_insn, CsFree> insn =
        DoDisasm(code.data(), code.size(), address, 0);
    if (insn)
      return std::string(insn->mnemonic) + " " + insn->op_str;
    else
      return ("<unknown>");
  }

 private:
  csh capstone_;
};

Disasm* CreateDisasm(MachineType type, Endianness endianness, size_t wordSize) {
  Disasm* disasm = new Disasm();
  if (disasm->Init(type, endianness, wordSize) < 0) {
    delete disasm;
    throw std::runtime_error("Failed to initialize disassembler");
  }
  return disasm;
}

template <typename W>
class Dumper {
 public:
  Dumper() : insnCount_(0) {}

  template <Endianness E>
  int Init(HeaderEntry<E, W> entry, size_t /* expectedInsnCount */) {
    std::printf("Endian            : %s\n", GetEndiannessStrPy(E));
    std::printf("Word              : %s\n", sizeof(W) == 4 ? "I" : "Q");
    std::printf("Word size         : %zu\n", sizeof(W));
    std::printf("Machine           : %s\n",
                GetMachineTypeStr(entry.GetMachineType()));
    std::printf("Regs size         : %d\n", entry.GetRegsSize());
    return disasmEngine_.Init(entry.GetMachineType(), E, sizeof(W));
  }

  template <Endianness E>
  int operator()(size_t i, LdStEntry<E, W> entry) {
    std::printf("[%10zu] 0x%08" PRIx32 ": %s uint%zu_t [0x%" PRIx64 "] ", i,
                entry.GetInsnSeq(), GetTagStr(entry.GetTlv().GetTag()),
                static_cast<size_t>(entry.GetSize() * 8),
                static_cast<std::uint64_t>(entry.GetAddr()));
    ValueDump<E>(entry.GetValue(), entry.GetSize());
    std::printf("\n");
    return 0;
  }

  template <Endianness E>
  int operator()(size_t i, InsnEntry<E, W> entry) {
    std::printf("[%10zu] 0x%08" PRIx32 ": %s 0x%016" PRIx64 " ", i,
                entry.GetInsnSeq(), GetTagStr(entry.GetTlv().GetTag()),
                static_cast<std::uint64_t>(entry.GetPc()));
    HexDump(stdout, entry.GetValue(), entry.GetSize());
    std::unique_ptr<cs_insn, CsFree> insn = disasmEngine_.DoDisasm(
        entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
    if (insn)
      std::printf(" %s %s\n", insn->mnemonic, insn->op_str);
    else
      std::printf(" <unknown>\n");
    return 0;
  }

  template <Endianness E>
  int operator()(size_t i, InsnExecEntry<E, W> entry) {
    std::printf("[%10zu] 0x%08" PRIx32 ": %s\n", i, entry.GetInsnSeq(),
                GetTagStr(entry.GetTlv().GetTag()));
    insnCount_++;
    return 0;
  }

  template <Endianness E>
  int operator()(size_t i, LdStNxEntry<E, W> entry) {
    std::printf("[%10zu] 0x%08" PRIx32 ": %s uint%zu_t [0x%" PRIx64 "]\n", i,
                entry.GetInsnSeq(), GetTagStr(entry.GetTlv().GetTag()),
                static_cast<size_t>(entry.GetSize() * 8),
                static_cast<std::uint64_t>(entry.GetAddr()));
    return 0;
  }

  template <Endianness E>
  int operator()(size_t i, MmapEntry<E, W> entry) {
    std::printf("[%10zu] %s %016" PRIx64 "-%016" PRIx64 " %c%c%c %s\n", i,
                GetTagStr(entry.GetTlv().GetTag()),
                static_cast<std::uint64_t>(entry.GetStart()),
                static_cast<std::uint64_t>(entry.GetEnd() + 1),
                entry.GetFlags() & 1 ? 'r' : '-',
                entry.GetFlags() & 2 ? 'w' : '-',
                entry.GetFlags() & 4 ? 'x' : '-', entry.GetValue());
    return 0;
  }

  int Complete() {
    std::printf("Insns             : %zu\n", insnCount_);
    return 0;
  }

 private:
  size_t insnCount_;
  Disasm disasmEngine_;
};

struct TagStats {
  TagStats() : count(0), size(0) {}

  template <Endianness E, typename W>
  int AddTlv(Tlv<E, W> tlv) {
    count++;
    size += tlv.GetAlignedLength();
    return 0;
  }

  size_t count;
  size_t size;
};

struct Stats {
  std::map<Tag, TagStats> tagStats;
};

struct EntryPy {
  explicit EntryPy(size_t index) : index(index) {}
  EntryPy(const EntryPy&) = delete;
  virtual ~EntryPy() = default;

  virtual Tag GetTag() const = 0;

  std::uint64_t index;
};

template <Endianness E, typename W>
struct EntryPyEW : public EntryPy {
  using EntryPy::EntryPy;

  const std::uint8_t* GetData() const {
    return reinterpret_cast<const std::uint8_t*>(this + 1);
  }

  Tag GetTag() const override { return Tlv<E, W>(GetData()).GetTag(); }
};

template <Endianness E, typename W, typename B,
          template <Endianness, typename, typename> typename Entry>
Entry<E, W, EntryPyEW<E, W>>* CreateEntryPy(size_t index,
                                            Entry<E, W, B> entry) {
  using Result = Entry<E, W, EntryPyEW<E, W>>;
  static_assert(sizeof(Result) == sizeof(EntryPy));
  size_t srcLength = entry.GetTlv().GetLength();
  size_t size = sizeof(Result) + srcLength;
  Result* result = reinterpret_cast<Result*>(new char[size]);
  void* dst = result + 1;
  const void* src = entry.GetData();
  std::memcpy(dst, src, srcLength);
  new (result) Result(index);
  return result;
}

struct TraceEntry2Py {
  template <typename Entry>
  int operator()(size_t index, Entry entry) {
    py = CreateEntryPy(index, entry);
    return 0;
  }

  EntryPy* py;
};

struct Seeker {
  Seeker()
      : insnIndex(std::numeric_limits<size_t>::max()),
        prevInsnSeq(std::numeric_limits<std::uint32_t>::max()) {}

  template <Endianness E, typename W>
  int operator()(size_t /* index */, LdStEntry<E, W> entry) {
    return HandleInsnSeq(entry.GetInsnSeq());
  }

  template <Endianness E, typename W>
  int operator()(size_t /* index */, InsnEntry<E, W> /* entry */) {
    return 0;
  }

  template <Endianness E, typename W>
  int operator()(size_t /* index */, InsnExecEntry<E, W> entry) {
    return HandleInsnSeq(entry.GetInsnSeq());
  }

  template <Endianness E, typename W>
  int operator()(size_t /* index */, LdStNxEntry<E, W> entry) {
    return HandleInsnSeq(entry.GetInsnSeq());
  }

  template <Endianness E, typename W>
  int operator()(size_t /* index */, MmapEntry<E, W> /* entry */) {
    return 0;
  }

  int HandleInsnSeq(std::uint32_t insnSeq) {
    if (insnSeq != prevInsnSeq) {
      insnIndex++;
      prevInsnSeq = insnSeq;
    }
    return 0;
  }

  size_t insnIndex;
  std::uint32_t prevInsnSeq;
};

struct StatsGatherer {
  template <Endianness E, typename W>
  int Init(HeaderEntry<E, W> entry, size_t /* expectedInsnCount */) {
    return HandleTlv(entry.GetTlv());
  }

  template <typename Entry>
  int operator()(size_t /* i */, Entry entry) {
    return HandleTlv(entry.GetTlv());
  }

  template <Endianness E, typename W>
  int HandleTlv(Tlv<E, W> tlv) {
    return stats.tagStats[tlv.GetTag()].AddTlv(tlv);
  }

  Stats stats;
};

struct MmapEntryGatherer {
  template <Endianness E, typename W>
  int operator()(size_t i, MmapEntry<E, W> entry) {
    mmapEntries.append(
        boost::python::object(boost::python::ptr(CreateEntryPy(i, entry))));
    return 0;
  }

  template <typename Entry>
  int operator()(size_t /* i */, Entry /* entry */) {
    return 0;
  }

  boost::python::list mmapEntries;
};

struct InsnIndexEntry {
  size_t insnIndex;
  size_t fileOffset;
  size_t entryIndex;
};

class TraceBase {
 public:
  template <typename V>
  static int Visit(const char* path, const V& v);
  static TraceBase* Load(const char* path);
  template <typename V>
  void Downcast(const V& v);

  virtual ~TraceBase() = default;
  virtual Endianness GetEndianness() = 0;
  virtual size_t GetWordSize() = 0;
  virtual MachineType GetMachineType() = 0;
  virtual std::uint16_t GetRegsSize() = 0;
  virtual boost::python::object Next() = 0;
  virtual void SeekInsn(std::uint32_t index) = 0;
  virtual Stats GatherStats() = 0;
  virtual void BuildInsnIndex(const char* path, size_t stepShift) = 0;
  void BuildInsnIndexDefault(const char* path) { BuildInsnIndex(path, 8); }
  virtual void LoadInsnIndex(const char* path) = 0;
  virtual boost::python::list GetMmapEntries() = 0;
};

template <Endianness _E, typename _W>
class Trace : public TraceBase {
 public:
  static constexpr Endianness E = _E;
  using W = _W;

  Trace(void* data, size_t length)
      : data_(static_cast<std::uint8_t*>(data)),
        length_(length),
        cur_(data_),
        end_(cur_ + length_),
        entryIndex_(0),
        header_(cur_) {}
  virtual ~Trace() { munmap(data_, length_); }

  template <typename V>
  static int CreateAndVisit(std::uint8_t* data, size_t length, const V& v) {
    int err;
    Trace<E, W>* trace = new Trace<E, W>(data, length);
    if ((err = trace->Init()) < 0) {
      delete trace;
      return err;
    }
    return v(trace);
  }

  int Init() {
    if (!Have(HeaderEntry<E, W>::kFixedLength)) return -EINVAL;
    if (!Advance(header_.GetTlv().GetAlignedLength())) return -EINVAL;
    return 0;
  }

  template <typename V>
  int InitVisitor(V* visitor) {
    // On average, one executed instruction takes 132.7 bytes in the trace file.
    return visitor->Init(header_, length_ / 128);
  }

  template <template <typename> typename V, typename... Args>
  int Visit(size_t start, size_t end, Args&&... args) {
    V<W> visitor(std::forward<Args>(args)...);
    return Visit(&visitor, start, end);
  }

  template <typename V>
  int Visit(V* visitor, size_t start = std::numeric_limits<size_t>::min(),
            size_t end = std::numeric_limits<size_t>::max()) {
    int err;
    if ((err = InitVisitor(visitor)) < 0) return err;
    while (cur_ != end_)
      if ((err = VisitOne(visitor, start, end)) < 0) return err;
    if ((err = visitor->Complete()) < 0) return err;
    return 0;
  }

  template <typename V>
  int VisitOne(V* visitor, size_t start = std::numeric_limits<size_t>::min(),
               size_t end = std::numeric_limits<size_t>::max()) {
    if (!Have(Tlv<E, W>::kFixedLength)) return -EINVAL;
    Tlv<E, W> tlv(cur_);
    if (!Have(tlv.GetAlignedLength())) return -EINVAL;
    if (entryIndex_ >= start && entryIndex_ < end) {
      Tag tag = tlv.GetTag();
      int err = -EINVAL;
      switch (tag) {
        case Tag::MT_LOAD:
        case Tag::MT_STORE:
        case Tag::MT_REG:
        case Tag::MT_GET_REG:
        case Tag::MT_PUT_REG:
          err = (*visitor)(entryIndex_, LdStEntry<E, W>(cur_));
          break;
        case Tag::MT_INSN:
          err = (*visitor)(entryIndex_, InsnEntry<E, W>(cur_));
          break;
        case Tag::MT_INSN_EXEC:
          err = (*visitor)(entryIndex_, InsnExecEntry<E, W>(cur_));
          break;
        case Tag::MT_GET_REG_NX:
        case Tag::MT_PUT_REG_NX:
          err = (*visitor)(entryIndex_, LdStNxEntry<E, W>(cur_));
          break;
        case Tag::MT_MMAP:
          err = (*visitor)(entryIndex_, MmapEntry<E, W>(cur_));
          break;
        default:
          return -EINVAL;
      }
      if (err < 0) return err;
    }
    if (!Advance(tlv.GetAlignedLength())) return -EINVAL;
    entryIndex_++;
    return 0;
  }

  Endianness GetEndianness() override { return E; }

  size_t GetWordSize() override { return sizeof(W); }

  MachineType GetMachineType() override { return header_.GetMachineType(); }

  std::uint16_t GetRegsSize() override { return header_.GetRegsSize(); }

  boost::python::object Next() override {
    if (cur_ == end_) boost::python::objects::stop_iteration_error();
    TraceEntry2Py visitor;
    int err = VisitOne(&visitor);
    if (err < 0) throw std::runtime_error("Failed to parse the next entry");
    return boost::python::object(boost::python::ptr(visitor.py));
  }

  void SeekInsn(std::uint32_t index) override {
    Seeker visitor;
    if (insnIndex_.IsInitalized()) {
      MmVector<InsnIndexEntry>::const_iterator it = std::upper_bound(
          insnIndex_.begin(), insnIndex_.end(), index,
          [](std::uint32_t insnIndex, const InsnIndexEntry& entry) {
            return insnIndex < entry.insnIndex;
          });
      --it;
      Rewind(*it);
      visitor.insnIndex = it->insnIndex - 1;
    } else {
      Rewind();
    }
    while (true) {
      if (cur_ == end_) throw std::invalid_argument("No such insn");
      std::uint8_t* prev = cur_;
      int err = VisitOne(&visitor);
      if (err < 0) throw std::runtime_error("Failed to parse the next entry");
      if (visitor.insnIndex == index) {
        cur_ = prev;
        entryIndex_--;
        break;
      }
    }
  }

  Stats GatherStats() override {
    StatsGatherer visitor;
    if (InitVisitor(&visitor) < 0)
      throw std::runtime_error("Failed to parse the header");
    while (cur_ != end_)
      if (VisitOne(&visitor) < 0)
        throw std::runtime_error("Failed to parse the next entry");
    return visitor.stats;
  }

  void BuildInsnIndex(const char* path, size_t stepShift) override {
    if (insnIndex_.Init(path, InitMode::CreatePersistent) < 0)
      throw std::runtime_error("Failed to create index");
    size_t stepMask = (1 << stepShift) - 1;
    Rewind();
    Seeker visitor;
    size_t prevInsnIndex = visitor.insnIndex;
    while (cur_ != end_) {
      std::uint8_t* prev = cur_;
      if (VisitOne(&visitor) < 0)
        throw std::runtime_error("Failed to parse the next entry");
      if (visitor.insnIndex != prevInsnIndex) {
        if ((visitor.insnIndex & stepMask) == 0)
          insnIndex_.push_back(InsnIndexEntry{visitor.insnIndex,
                                              static_cast<size_t>(prev - data_),
                                              entryIndex_ - 1});
        prevInsnIndex = visitor.insnIndex;
      }
    }
  }

  void LoadInsnIndex(const char* path) override {
    if (insnIndex_.Init(path, InitMode::OpenExisting) < 0)
      throw std::runtime_error("Failed to load index");
  }

  class ScopedRewind {
   public:
    explicit ScopedRewind(Trace* trace)
        : trace_(trace),
          saved_({static_cast<size_t>(-1),
                  static_cast<size_t>(trace->cur_ - trace->data_),
                  trace->entryIndex_}) {}
    ScopedRewind(const ScopedRewind&) = delete;
    ~ScopedRewind() { trace_->Rewind(saved_); }

   private:
    Trace* trace_;
    InsnIndexEntry saved_;
  };

  boost::python::list GetMmapEntries() override {
    ScopedRewind scopedRewind(this);
    if (insnIndex_.IsInitalized())
      Rewind(insnIndex_[insnIndex_.size() - 1]);
    else
      Rewind();
    MmapEntryGatherer visitor;
    while (cur_ != end_)
      if (VisitOne(&visitor) < 0)
        throw std::runtime_error("Failed to parse the next entry");
    return visitor.mmapEntries;
  }

 private:
  bool Have(size_t n) const { return cur_ + n <= end_; }

  bool Advance(size_t n) {
    std::uint8_t* next = cur_ + n;
    if (next > end_) return false;
    cur_ = next;
    return true;
  }

  void Rewind() {
    cur_ = data_ + header_.GetTlv().GetAlignedLength();
    entryIndex_ = 0;
  }

  void Rewind(const InsnIndexEntry& entry) {
    cur_ = data_ + entry.fileOffset;
    entryIndex_ = entry.entryIndex;
  }

  std::uint8_t* data_;
  size_t length_;
  std::uint8_t* cur_;
  std::uint8_t* end_;
  size_t entryIndex_;
  HeaderEntry<E, W> header_;
  MmVector<InsnIndexEntry> insnIndex_;
};

int MmapFile(const char* path, size_t minSize, std::uint8_t** p,
             size_t* length) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) return -errno;
  struct stat stat;
  if (fstat(fd, &stat) < 0) {
    int err = errno;
    close(fd);
    return -err;
  }
  if (static_cast<size_t>(stat.st_size) < minSize) {
    close(fd);
    return -EINVAL;
  }
  void* data = mmap(nullptr, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  int err = errno;
  close(fd);
  if (data == MAP_FAILED) return -err;
  *p = static_cast<std::uint8_t*>(data);
  *length = static_cast<size_t>(stat.st_size);
  return 0;
}

template <typename V>
int TraceBase::Visit(const char* path, const V& v) {
  int err;
  std::uint8_t* data;
  size_t length;
  if ((err = MmapFile(path, 2, &data, &length)) < 0) return err;
  if (data == MAP_FAILED) return -ENOMEM;
  switch (data[0] << 8 | data[1]) {
    case 'M' << 8 | '4':
      return Trace<Endianness::Big, std::uint32_t>::CreateAndVisit(data, length,
                                                                   v);
    case 'M' << 8 | '8':
      return Trace<Endianness::Big, std::uint64_t>::CreateAndVisit(data, length,
                                                                   v);
    case '4' << 8 | 'M':
      return Trace<Endianness::Little, std::uint32_t>::CreateAndVisit(
          data, length, v);
    case '8' << 8 | 'M':
      return Trace<Endianness::Little, std::uint64_t>::CreateAndVisit(
          data, length, v);
    default:
      munmap(data, length);
      return -EINVAL;
  }
}

template <template <typename> typename V, typename... Args>
int VisitFile(const char* path, size_t start, size_t end, Args&&... args) {
  return TraceBase::Visit(path, [start, end, &args...](auto trace) {
    int err = trace->template Visit<V>(start, end, std::forward<Args>(args)...);
    delete trace;
    return err;
  });
}

TraceBase* TraceBase::Load(const char* path) {
  TraceBase* result = nullptr;
  Visit(path, [&result](TraceBase* trace) -> int {
    result = trace;
    return 0;
  });
  return result;
}

template <typename V>
void TraceBase::Downcast(const V& v) {
  switch (GetEndianness()) {
    case Endianness::Little:
      switch (GetWordSize()) {
        case 4:
          v(static_cast<Trace<Endianness::Little, std::uint32_t>*>(this));
          break;
        case 8:
          v(static_cast<Trace<Endianness::Little, std::uint64_t>*>(this));
          break;
        default:
          __builtin_unreachable();
      }
      break;
    case Endianness::Big:
      switch (GetWordSize()) {
        case 4:
          v(static_cast<Trace<Endianness::Big, std::uint32_t>*>(this));
          break;
        case 8:
          v(static_cast<Trace<Endianness::Big, std::uint64_t>*>(this));
          break;
        default:
          __builtin_unreachable();
      }
      break;
    default:
      __builtin_unreachable();
  }
}  // namespace

int DumpFile(const char* path, size_t start, size_t end) {
  return VisitFile<Dumper>(path, start, end);
}

template <typename W>
struct Range {
  W startAddr;
  W endAddr;
};

template <typename W>
struct Def {
  Range<W> range;
};

template <typename W>
struct InsnInCode {
  W pc;
  std::uint32_t textIndex;
  std::uint32_t textSize;
};

struct InsnInTrace {
  std::uint32_t codeIndex;
  std::uint32_t regUseStartIndex;
  std::uint32_t regUseEndIndex;
  std::uint32_t memUseStartIndex;
  std::uint32_t memUseEndIndex;
  std::uint32_t regDefStartIndex;
  std::uint32_t regDefEndIndex;
  std::uint32_t memDefStartIndex;
  std::uint32_t memDefEndIndex;
};

size_t GetFirstPrimeGreaterThanOrEqualTo(size_t value) {
  static std::vector<size_t> primes = {3};
  value |= 1;
  while (true) {
    size_t valueSqrt = static_cast<size_t>(std::sqrt(value));
    while (primes.back() <= valueSqrt)
      primes.push_back(GetFirstPrimeGreaterThanOrEqualTo(primes.back() + 1));
    bool isPrime = true;
    for (size_t primeIndex = 0; primes[primeIndex] <= valueSqrt; primeIndex++)
      if (value % primes[primeIndex] == 0) {
        isPrime = false;
        break;
      }
    if (isPrime) return value;
    value += 2;
  }
}

template <typename W>
struct PartialUse {
  std::uint32_t first;  // uses_ index
  Range<W> second;
};

template <typename W>
static const PartialUse<W>* ScanPartialUses(const PartialUse<W>* partialUses,
                                            size_t partialUseCount,
                                            std::uint32_t useIndex) {
  for (size_t entryIndex = 0; entryIndex < partialUseCount; entryIndex++) {
    const PartialUse<W>& partialUse = partialUses[entryIndex];
    if (partialUse.first == useIndex ||
        partialUse.first == static_cast<std::uint32_t>(-1))
      return &partialUse;
  }
  return nullptr;
}

template <typename W>
static const PartialUse<W>& FindPartialUse(const PartialUse<W>* hashTable,
                                           size_t hashTableSize,
                                           std::uint32_t useIndex) {
  size_t entryIndex = useIndex % hashTableSize;
  const PartialUse<W>* use = ScanPartialUses(
      hashTable + entryIndex, hashTableSize - entryIndex, useIndex);
  if (use == nullptr) use = ScanPartialUses(hashTable, entryIndex, useIndex);
  assert(use != nullptr);
  return *use;
}

template <typename W>
class PartialUses {
 public:
  using const_iterator = const PartialUse<W>*;

  PartialUses() : load_(0), maxLoad_(0) {}

  [[nodiscard]] int Init(const char* path, InitMode mode) {
    path_ = path;
    int err;
    if ((err = entries_.Init(path, mode)) < 0) return err;
    if (mode != InitMode::OpenExisting) {
      entries_.resize(11);
      for (size_t i = 0; i < entries_.size(); i++) entries_[i].first = -1;
    }
    maxLoad_ = entries_.size() / 2;
    return 0;
  }

  PartialUse<W>* end() const { return nullptr; }

  Range<W>& operator[](std::uint32_t useIndex) {
    PartialUse<W>& result1 = const_cast<PartialUse<W>&>(
        FindPartialUse(entries_.data(), entries_.size(), useIndex));
    if (result1.first == useIndex) return result1.second;
    result1.first = useIndex;
    load_ += 1;
    if (load_ <= maxLoad_) return result1.second;
    reserve(load_ * 2);
    PartialUse<W>& result2 = const_cast<PartialUse<W>&>(
        FindPartialUse(entries_.data(), entries_.size(), useIndex));
    assert(result2.first == useIndex);
    return result2.second;
  }

  const PartialUse<W>* find(std::uint32_t useIndex) const {
    const PartialUse<W>& result =
        FindPartialUse(entries_.data(), entries_.size(), useIndex);
    return result.first == useIndex ? &result : nullptr;
  }

  const MmVector<PartialUse<W>>& GetData() const { return entries_; }

  void reserve(size_t n) {
    size_t newSize = GetFirstPrimeGreaterThanOrEqualTo(n * 2);
    MmVector<PartialUse<W>> oldEntries;
    if (oldEntries.Init(path_.c_str(), InitMode::CreateTemporary) < 0)
      throw std::bad_alloc();
    oldEntries.insert(oldEntries.end(), entries_.begin(), entries_.end());
    size_t oldSize = entries_.size();
    entries_.resize(newSize);
    for (size_t i = 0; i < newSize; i++)
      entries_[i].first = static_cast<std::uint32_t>(-1);
    for (size_t oldEntryIndex = 0; oldEntryIndex < oldSize; oldEntryIndex++) {
      const PartialUse<W>& oldEntry = oldEntries[oldEntryIndex];
      if (oldEntry.first == static_cast<std::uint32_t>(-1)) continue;
      PartialUse<W>& newEntry = const_cast<PartialUse<W>&>(
          FindPartialUse(entries_.data(), newSize, oldEntry.first));
      assert(newEntry.first == static_cast<std::uint32_t>(-1));
      newEntry = oldEntry;
    }
    maxLoad_ = newSize / 2;
  }

 private:
  MmVector<PartialUse<W>> entries_;
  size_t load_;
  size_t maxLoad_;
  std::string path_;
};

template <typename W>
struct ResolvedUse {
  const Range<W>* range;
  std::uint32_t traceIndex;
};

template <typename W, typename UseIterator, typename DefIterator,
          typename PartialUseIterator, typename InsnInTraceIterator>
ResolvedUse<W> ResolveUse(std::uint32_t useIndex, UseIterator uses,
                          DefIterator defs, PartialUseIterator partialUses,
                          size_t partialUseCount,
                          InsnInTraceIterator traceBegin,
                          InsnInTraceIterator traceEnd,
                          std::uint32_t InsnInTrace::*startDefIndex) {
  std::uint32_t defIndex = uses[useIndex];
  const Range<W>* range;
  const PartialUse<W>& partialUse =
      FindPartialUse(partialUses, partialUseCount, useIndex);
  if (partialUse.first == static_cast<std::uint32_t>(-1))
    range = &(defs + defIndex)->range;
  else
    range = &partialUse.second;

  InsnInTraceIterator it =
      std::upper_bound(traceBegin, traceEnd, defIndex,
                       [startDefIndex](std::uint32_t defIndex,
                                       const InsnInTrace& trace) -> bool {
                         return defIndex < trace.*startDefIndex;
                       });
  --it;
  std::uint32_t traceIndex = static_cast<std::uint32_t>(it - traceBegin);

  return ResolvedUse<W>{range, traceIndex};
}

const char kPlaceholder[] = "{}";
constexpr size_t kPlaceholderLength = sizeof(kPlaceholder) - 1;

struct PathWithPlaceholder {
  std::string_view before[2];
  std::string_view after;

  int Init(const char* path, const char* description) {
    const char* placeholder = std::strstr(path, kPlaceholder);
    if (placeholder == nullptr) {
      std::cerr << description << " path must contain a " << kPlaceholder
                << " placeholder" << std::endl;
      return -EINVAL;
    }
    before[0] = std::string_view(path, placeholder - path);
    after = placeholder + kPlaceholderLength;
    return 0;
  }

  std::string Get(const char* value) const {
    std::string path;
    size_t len = strlen(value);
    path.reserve(before[0].length() + before[1].length() + len +
                 after.length());
    path.append(before[0]);
    path.append(before[1]);
    path.append(std::string_view(value, len));
    path.append(after);
    return path;
  }
};

template <typename W>
class UdState {
 public:
  [[nodiscard]] int Init(const PathWithPlaceholder& path, InitMode mode,
                         size_t expectedUseCount, size_t expectedDefCount,
                         size_t expectedPartialUseCount) {
    int err;
    if ((err = uses_.Init(path.Get("uses").c_str(), mode)) < 0) return err;
    if ((err = defs_.Init(path.Get("defs").c_str(), mode)) < 0) return err;
    if ((err = partialUses_.Init(path.Get("partial-uses").c_str(), mode)) < 0)
      return err;
    if (mode != InitMode::OpenExisting) {
      uses_.reserve(expectedUseCount);
      defs_.reserve(expectedDefCount);
      partialUses_.reserve(expectedPartialUseCount);
    }
    return 0;
  }

  void AddUses(W startAddr, W size) {
    W endAddr = startAddr + size;
    for (It it = addressSpace_.lower_bound(startAddr + 1);
         it != addressSpace_.end() && it->second.startAddr < endAddr; ++it) {
      std::uint32_t useIndex = static_cast<std::uint32_t>(uses_.size());
      uses_.push_back(it->second.defIndex);
      const Def<W>& def = defs_[it->second.defIndex];
      W maxStartAddr = std::max(startAddr, it->second.startAddr);
      W minEndAddr = std::min(endAddr, it->first);
      if (def.range.startAddr != maxStartAddr ||
          def.range.endAddr != minEndAddr)
        partialUses_[useIndex] = Range<W>{maxStartAddr, minEndAddr};
    }
  }

  int AddDefs(W startAddr, W size) {
    W endAddr = startAddr + size;
    affectedEntries_.clear();
    It firstAffected = addressSpace_.lower_bound(startAddr + 1);
    It lastAffected;
    for (lastAffected = firstAffected; lastAffected != addressSpace_.end() &&
                                       lastAffected->second.startAddr < endAddr;
         lastAffected++)
      affectedEntries_.push_back(*lastAffected);
    addressSpace_.erase(firstAffected, lastAffected);
    for (const Entry& entry : affectedEntries_) {
      W entryStartAddr = entry.second.startAddr;
      W entryEndAddr = entry.first;
      std::uint32_t entryDefIndex = entry.second.defIndex;
      if (startAddr <= entryStartAddr) {
        if (endAddr < entryEndAddr) {
          // Left overlap.
          addressSpace_[entryEndAddr] = EntryValue{endAddr, entryDefIndex};
        } else {
          // Outer overlap.
        }
      } else {
        if (endAddr < entryEndAddr) {
          // Inner overlap.
          addressSpace_[startAddr] = EntryValue{entryStartAddr, entryDefIndex};
          addressSpace_[entryEndAddr] = EntryValue{endAddr, entryDefIndex};
        } else {
          // Right overlap.
          addressSpace_[startAddr] = EntryValue{entryStartAddr, entryDefIndex};
        }
      }
    }
    AddDef(startAddr, endAddr);
    return 0;
  }

  size_t GetUseCount() const { return uses_.size(); }
  size_t GetDefCount() const { return defs_.size(); }
  size_t GetPartialUseCount() const { return partialUses_.GetData().size(); }

  void DumpUses(std::uint32_t startIndex, std::uint32_t endIndex,
                const MmVector<InsnInTrace>& trace,
                std::uint32_t InsnInTrace::*startDefIndex) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      ResolvedUse<W> use = ResolveUse(useIndex, trace, startDefIndex);
      std::printf(useIndex == startIndex
                      ? "0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]"
                      : ", 0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]",
                  static_cast<std::uint64_t>(use.range->startAddr),
                  static_cast<std::uint64_t>(use.range->endAddr),
                  use.traceIndex);
    }
  }

  void DumpDefs(std::uint32_t startIndex, std::uint32_t endIndex) const {
    for (std::uint32_t defIndex = startIndex; defIndex < endIndex; defIndex++)
      std::printf(defIndex == startIndex ? "0x%" PRIx64 "-0x%" PRIx64
                                         : ", 0x%" PRIx64 "-0x%" PRIx64,
                  static_cast<std::uint64_t>(defs_[defIndex].range.startAddr),
                  static_cast<std::uint64_t>(defs_[defIndex].range.endAddr));
  }

  void DumpUsesDot(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const MmVector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startDefIndex,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      ResolvedUse<W> use = ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f,
                   "    %" PRIu32 " -> %" PRIu32 " [label=\"%s0x%" PRIx64
                   "-0x%" PRIx64 "\"]\n",
                   traceIndex, use.traceIndex, prefix,
                   static_cast<std::uint64_t>(use.range->startAddr),
                   static_cast<std::uint64_t>(use.range->endAddr));
    }
  }

  void DumpUsesHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex, const MmVector<InsnInTrace>& trace,
                    std::uint32_t InsnInTrace::*startDefIndex,
                    const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      ResolvedUse<W> use = ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f,
                   "            <a href=\"#%" PRIu32 "\">%s0x%" PRIx64
                   "-0x%" PRIx64 "</a>\n",
                   use.traceIndex, prefix,
                   static_cast<std::uint64_t>(use.range->startAddr),
                   static_cast<std::uint64_t>(use.range->endAddr));
    }
  }

  void DumpDefsHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex, const char* prefix) const {
    for (std::uint32_t i = startIndex; i < endIndex; i++)
      std::fprintf(f, "            %s0x%" PRIx64 "-0x%" PRIx64 "\n", prefix,
                   static_cast<std::uint64_t>(defs_[i].range.startAddr),
                   static_cast<std::uint64_t>(defs_[i].range.endAddr));
  }

  void DumpUsesCsv(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const MmVector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startDefIndex,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      ResolvedUse<W> use = ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f, "%" PRIu32 ",%" PRIu32 ",%s,%" PRIu64 ",%" PRIu64 "\n",
                   traceIndex, use.traceIndex, prefix,
                   static_cast<std::uint64_t>(use.range->startAddr),
                   static_cast<std::uint64_t>(use.range->endAddr));
    }
  }

  void AddDef(W startAddr, W endAddr) {
    std::uint32_t defIndex = static_cast<std::uint32_t>(defs_.size());
    Def<W>& def = defs_.emplace_back();
    def.range.startAddr = startAddr;
    def.range.endAddr = endAddr;
    addressSpace_[endAddr] = EntryValue{startAddr, defIndex};
  }

  ResolvedUse<W> ResolveUse(std::uint32_t useIndex,
                            const MmVector<InsnInTrace>& trace,
                            std::uint32_t InsnInTrace::*startDefIndex) const {
    return ::ResolveUse<W>(useIndex, uses_.begin(), defs_.begin(),
                           partialUses_.GetData().data(),
                           partialUses_.GetData().size(), trace.begin(),
                           trace.end(), startDefIndex);
  }

 private:
  MmVector<std::uint32_t> uses_;  // defs_ indices.
  // On average, 4% register and 12% memory uses are partial.
  PartialUses<W> partialUses_;
  MmVector<Def<W>> defs_;
  struct EntryValue {
    W startAddr;
    std::uint32_t defIndex;
  };
  // endAddr -> EntryValue.
  using AddressSpace = typename std::map<W, EntryValue>;
  using Entry = typename std::pair<W, EntryValue>;
  using It = typename AddressSpace::const_iterator;
  AddressSpace addressSpace_;
  // Avoid allocating memory each time in AddDefs().
  // There may be up to 64k affected defs.
  std::vector<Entry> affectedEntries_;
};

struct BinaryHeader {
  std::uint8_t magic[2];    // Analyzer endianness and traced program word size.
  MachineType machineType;  // Traced program machine type.
  Endianness endianness;    // Traced program endianness.
};

class UdBase {
 public:
  static UdBase* Analyze(TraceBase* trace);
  static UdBase* Load(const char* path);

  virtual ~UdBase() = default;
  [[nodiscard]] virtual int Init(const BinaryHeader& header) = 0;
  virtual std::vector<std::uint32_t> GetCodesForPc(std::uint64_t pc) const = 0;
  virtual std::uint64_t GetPcForCode(std::uint32_t code) const = 0;
  virtual std::string GetDisasmForCode(std::uint32_t code) const = 0;
  virtual std::vector<std::uint32_t> GetTracesForCode(
      std::uint32_t code) const = 0;
  virtual std::uint32_t GetCodeForTrace(std::uint32_t trace) const = 0;
  virtual std::vector<std::uint32_t> GetRegUsesForTrace(
      std::uint32_t trace) const = 0;
  virtual std::vector<std::uint32_t> GetMemUsesForTrace(
      std::uint32_t trace) const = 0;
  virtual std::uint32_t GetTraceForRegUse(std::uint32_t regUse) const = 0;
  virtual std::uint32_t GetTraceForMemUse(std::uint32_t memUse) const = 0;
};

template <typename W>
class Ud : public UdBase {
 public:
  Ud(const char* dot, const char* html, const char* csv, const char* binary,
     bool verbose)
      : dot_(dot), html_(html), csv_(csv), binary_(binary), verbose_(verbose) {}

  [[nodiscard]] int Init(InitMode mode, MachineType machineType,
                         Endianness endianness, size_t expectedInsnCount) {
    machineType_ = machineType;
    endianness_ = endianness;

    int err;
    if (csv_ != nullptr && (err = csvPath_.Init(csv_, "csv")) < 0) return err;

    if (mode == InitMode::CreateTemporary)
      binaryPath_.before[0] = "./";
    else if ((err = binaryPath_.Init(binary_, "binary")) < 0)
      return err;

    if ((err = trace_.Init(binaryPath_.Get("trace").c_str(), mode)) < 0)
      return err;
    if ((err = code_.Init(binaryPath_.Get("code").c_str(), mode)) < 0)
      return err;
    if ((err = text_.Init(binaryPath_.Get("text").c_str(), mode)) < 0)
      return err;
    binaryPath_.before[1] = "reg-";
    // On average, 1.69 register uses and 1.61 register defs per insn.
    if ((err = regState_.Init(binaryPath_, mode, expectedInsnCount * 7 / 4,
                              expectedInsnCount * 5 / 3,
                              expectedInsnCount / 10)) < 0)
      return err;
    // On average, 0.4 memory uses and 0.22 memory defs per insn.
    binaryPath_.before[1] = "mem-";
    if ((err = memState_.Init(binaryPath_, mode, expectedInsnCount / 2,
                              expectedInsnCount / 4, expectedInsnCount / 20)) <
        0)
      return err;
    binaryPath_.before[1] = std::string_view();

    // Add an initial catch-all entry.
    if (mode != InitMode::OpenExisting) {
      std::uint32_t codeIndex = static_cast<std::uint32_t>(code_.size());
      InsnInCode<W>& code = code_.emplace_back();
      code.pc = 0;
      code.textIndex = 0;
      code.textSize = 0;
      disasm_.emplace_back("<unknown>");
      trace_.reserve(expectedInsnCount);
      AddTrace(codeIndex);
      regState_.AddDef(0, std::numeric_limits<W>::max());
      memState_.AddDef(0, std::numeric_limits<W>::max());
    }

    if ((err = disasmEngine_.Init(machineType, endianness, sizeof(W))) < 0)
      return err;

    return 0;
  }

  [[nodiscard]] int Init(const BinaryHeader& header) override {
    return Init(InitMode::OpenExisting, header.machineType, header.endianness,
                0);
  }

  template <Endianness E>
  [[nodiscard]] int Init(HeaderEntry<E, W> entry, size_t expectedInsnCount) {
    return Init(binary_ == nullptr ? InitMode::CreateTemporary
                                   : InitMode::CreatePersistent,
                entry.GetMachineType(), E, expectedInsnCount);
  }

  template <Endianness E>
  int operator()(size_t /* i */, LdStEntry<E, W> entry) {
    int ret;
    if ((ret = HandleInsnSeq(entry.GetInsnSeq())) < 0) return ret;
    switch (entry.GetTlv().GetTag()) {
      case Tag::MT_LOAD:
        memState_.AddUses(entry.GetAddr(), entry.GetSize());
        return 0;
      case Tag::MT_STORE:
        return memState_.AddDefs(entry.GetAddr(), entry.GetSize());
      case Tag::MT_REG:
        return 0;
      case Tag::MT_GET_REG:
        regState_.AddUses(entry.GetAddr(), entry.GetSize());
        return 0;
      case Tag::MT_PUT_REG:
        return regState_.AddDefs(entry.GetAddr(), entry.GetSize());
      default:
        return -EINVAL;
    }
  }

  template <Endianness E>
  int operator()(size_t /* i */, InsnEntry<E, W> entry) {
    if (entry.GetInsnSeq() != static_cast<std::uint32_t>(code_.size()))
      return -EINVAL;
    InsnInCode<W>& code = code_.emplace_back();
    code.pc = entry.GetPc();
    code.textIndex = static_cast<std::uint32_t>(text_.size());
    text_.insert(text_.end(), entry.GetValue(),
                 entry.GetValue() + entry.GetSize());
    code.textSize = static_cast<std::uint32_t>(entry.GetSize());
    std::unique_ptr<cs_insn, CsFree> insn = disasmEngine_.DoDisasm(
        entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
    if (insn) {
      std::string& disasm = disasm_.emplace_back(insn->mnemonic);
      disasm += " ";
      disasm += insn->op_str;
    } else {
      disasm_.emplace_back("<unknown>");
    }
    return 0;
  }

  template <Endianness E>
  int operator()(size_t /* i */, InsnExecEntry<E, W> entry) {
    int ret;
    if ((ret = HandleInsnSeq(entry.GetInsnSeq())) < 0) return ret;
    return 0;
  }

  template <Endianness E>
  int operator()(size_t /* i */, LdStNxEntry<E, W> entry) {
    int ret;
    if ((ret = HandleInsnSeq(entry.GetInsnSeq())) < 0) return ret;
    switch (entry.GetTlv().GetTag()) {
      case Tag::MT_GET_REG_NX:
        regState_.AddUses(entry.GetAddr(), entry.GetSize());
        return 0;
      case Tag::MT_PUT_REG_NX:
        return regState_.AddDefs(entry.GetAddr(), entry.GetSize());
      default:
        return -EINVAL;
    }
  }

  template <Endianness E>
  int operator()(size_t /* i */, MmapEntry<E, W> /* entry */) {
    return 0;
  }

  int Complete() {
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = DumpDot()) < 0) return ret;
    if ((ret = DumpHtml()) < 0) return ret;
    if ((ret = DumpCsv()) < 0) return ret;
    if ((ret = DumpBinary()) < 0) return ret;
    return 0;
  }

  std::vector<std::uint32_t> GetCodesForPc(std::uint64_t pc) const override {
    std::vector<std::uint32_t> codes;
    for (std::uint32_t code = 0,
                       size = static_cast<std::uint32_t>(code_.size());
         code < size; code++)
      if (code_[code].pc == pc) codes.push_back(code);
    return codes;
  }

  std::uint64_t GetPcForCode(std::uint32_t code) const override {
    return code_[code].pc;
  }

  std::string GetDisasmForCode(std::uint32_t code) const override {
    const InsnInCode<W>& entry = code_[code];
    std::unique_ptr<cs_insn, CsFree> insn = disasmEngine_.DoDisasm(
        &text_[entry.textIndex], entry.textSize, entry.pc, 0);
    if (insn) {
      std::string disasm = insn->mnemonic;
      disasm += " ";
      disasm += insn->op_str;
      return disasm;
    } else {
      return "<unknown>";
    }
  }

  std::vector<std::uint32_t> GetTracesForCode(
      std::uint32_t code) const override {
    std::vector<std::uint32_t> traces;
    for (std::uint32_t trace = 0,
                       size = static_cast<std::uint32_t>(trace_.size());
         trace < size; trace++)
      if (trace_[trace].codeIndex == code) traces.push_back(trace);
    return traces;
  }

  std::uint32_t GetCodeForTrace(std::uint32_t trace) const override {
    return trace_[trace].codeIndex;
  }

  std::vector<std::uint32_t> GetRegUsesForTrace(
      std::uint32_t trace) const override {
    std::vector<std::uint32_t> regUses;
    for (std::uint32_t regUse = trace_[trace].regUseStartIndex;
         regUse < trace_[trace].regUseEndIndex; regUse++)
      regUses.push_back(regUse);
    return regUses;
  }

  std::vector<std::uint32_t> GetMemUsesForTrace(
      std::uint32_t trace) const override {
    std::vector<std::uint32_t> memUses;
    for (std::uint32_t memUse = trace_[trace].memUseStartIndex;
         memUse < trace_[trace].memUseEndIndex; memUse++)
      memUses.push_back(memUse);
    return memUses;
  }

  std::uint32_t GetTraceForRegUse(std::uint32_t regUse) const override {
    return regState_.ResolveUse(regUse, trace_, &InsnInTrace::regDefStartIndex)
        .traceIndex;
  }

  std::uint32_t GetTraceForMemUse(std::uint32_t memUse) const override {
    return memState_.ResolveUse(memUse, trace_, &InsnInTrace::memDefStartIndex)
        .traceIndex;
  }

 private:
  int Flush() {
    InsnInTrace& trace = trace_.back();
    trace.regUseEndIndex = static_cast<std::uint32_t>(regState_.GetUseCount());
    trace.memUseEndIndex = static_cast<std::uint32_t>(memState_.GetUseCount());
    trace.regDefEndIndex = static_cast<std::uint32_t>(regState_.GetDefCount());
    trace.memDefEndIndex = static_cast<std::uint32_t>(memState_.GetDefCount());

    if (verbose_) {
      InsnInCode<W>& code = code_[trace.codeIndex];
      std::printf("[%zu]0x%" PRIx64 ": ", trace_.size() - 1,
                  static_cast<std::uint64_t>(code.pc));
      HexDump(stdout, &text_[code.textIndex], code.textSize);
      std::printf(" %s reg_uses=[", disasm_[trace.codeIndex].c_str());
      regState_.DumpUses(trace.regUseStartIndex, trace.regUseEndIndex, trace_,
                         &InsnInTrace::regDefStartIndex);
      std::printf("] reg_defs=[");
      regState_.DumpDefs(trace.regDefStartIndex, trace.regDefEndIndex);
      std::printf("] mem_uses=[");
      memState_.DumpUses(trace.memUseStartIndex, trace.memUseEndIndex, trace_,
                         &InsnInTrace::memDefStartIndex);
      std::printf("] mem_defs=[");
      memState_.DumpDefs(trace.memDefStartIndex, trace.memDefEndIndex);
      std::printf("]\n");
    }

    return 0;
  }

  int AddTrace(std::uint32_t codeIndex) {
    InsnInTrace& trace = trace_.emplace_back();
    trace.codeIndex = codeIndex;
    trace.regUseStartIndex =
        static_cast<std::uint32_t>(regState_.GetUseCount());
    trace.memUseStartIndex =
        static_cast<std::uint32_t>(memState_.GetUseCount());
    trace.regDefStartIndex =
        static_cast<std::uint32_t>(regState_.GetDefCount());
    trace.memDefStartIndex =
        static_cast<std::uint32_t>(memState_.GetDefCount());
    return 0;
  }

  int HandleInsnSeq(std::uint32_t insnSeq) {
    if (trace_.back().codeIndex == insnSeq) return 0;
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = AddTrace(insnSeq)) < 0) return ret;
    return 0;
  }

  int DumpDot() const {
    if (dot_ == nullptr) return 0;
    std::FILE* f = std::fopen(dot_, "w");
    if (f == nullptr) return -errno;
    std::fprintf(f, "digraph ud {\n");
    for (std::uint32_t traceIndex = 0; traceIndex < trace_.size();
         traceIndex++) {
      const InsnInTrace& trace = trace_[traceIndex];
      const InsnInCode<W>& code = code_[trace.codeIndex];
      std::fprintf(
          f, "    %" PRIu32 " [label=\"[%" PRIu32 "] 0x%" PRIx64 ": %s\"]\n",
          traceIndex, traceIndex, static_cast<std::uint64_t>(code.pc),
          disasm_[trace.codeIndex].c_str());
      regState_.DumpUsesDot(f, traceIndex, trace.regUseStartIndex,
                            trace.regUseEndIndex, trace_,
                            &InsnInTrace::regDefStartIndex, "r");
      memState_.DumpUsesDot(f, traceIndex, trace.memUseStartIndex,
                            trace.memUseEndIndex, trace_,
                            &InsnInTrace::memDefStartIndex, "m");
    }
    std::fprintf(f, "}\n");
    std::fclose(f);
    return 0;
  }

  int DumpHtml() const {
    if (html_ == nullptr) return 0;
    std::FILE* f = std::fopen(html_, "w");
    if (f == nullptr) return -errno;
    std::fprintf(f,
                 "<!DOCTYPE html>\n"
                 "<html>\n"
                 "<head>\n"
                 "<title>ud</title>\n"
                 "</head>\n"
                 "<body>\n"
                 "<table>\n"
                 "    <tr>\n"
                 "        <th>Seq</th>\n"
                 "        <th>Address</th>\n"
                 "        <th>Bytes</th>\n"
                 "        <th>Instruction</th>\n"
                 "        <th>Uses</th>\n"
                 "        <th>Defs</th>\n"
                 "    </tr>\n");
    for (std::uint32_t traceIndex = 0; traceIndex < trace_.size();
         traceIndex++) {
      const InsnInTrace& trace = trace_[traceIndex];
      const InsnInCode<W>& code = code_[trace.codeIndex];
      std::fprintf(f,
                   "    <tr id=\"%" PRIu32
                   "\">\n"
                   "        <td>%" PRIu32
                   "</td>\n"
                   "        <td>0x%" PRIx64
                   "</td>\n"
                   "        <td>",
                   traceIndex, traceIndex, static_cast<std::uint64_t>(code.pc));
      HexDump(f, &text_[code.textIndex], code.textSize);
      std::fprintf(f,
                   "</td>\n"
                   "        <td>");
      HtmlDump(f, disasm_[trace.codeIndex].c_str());
      std::fprintf(f,
                   "</td>\n"
                   "        <td>\n");
      regState_.DumpUsesHtml(f, trace.regUseStartIndex, trace.regUseEndIndex,
                             trace_, &InsnInTrace::regDefStartIndex, "r");
      memState_.DumpUsesHtml(f, trace.memUseStartIndex, trace.memUseEndIndex,
                             trace_, &InsnInTrace::memDefStartIndex, "m");
      std::fprintf(f,
                   "        </td>\n"
                   "        <td>\n");
      regState_.DumpDefsHtml(f, trace.regDefStartIndex, trace.regDefEndIndex,
                             "r");
      memState_.DumpDefsHtml(f, trace.memDefStartIndex, trace.memDefEndIndex,
                             "m");
      std::fprintf(f,
                   "        </td>\n"
                   "    </tr>\n");
    }
    std::fprintf(f,
                 "</table>\n"
                 "</body>\n"
                 "</html>\n");
    std::fclose(f);
    return 0;
  }

  int DumpCodeCsv(const char* path) const {
    std::FILE* f = std::fopen(path, "w");
    if (f == nullptr) return -errno;
    for (std::uint32_t codeIndex = 0; codeIndex < code_.size(); codeIndex++) {
      const InsnInCode<W>& code = code_[codeIndex];
      std::fprintf(f, "%" PRIu32 ",%" PRIu64 ",", codeIndex,
                   static_cast<std::uint64_t>(code_[codeIndex].pc));
      HexDump(f, &text_[code.textIndex], code.textSize);
      std::fprintf(f, ",\"%s\"\n", disasm_[codeIndex].c_str());
    }
    std::fclose(f);
    return 0;
  }

  int DumpTraceCsv(const char* path) const {
    std::FILE* f = std::fopen(path, "w");
    if (f == nullptr) return -errno;
    for (std::uint32_t traceIndex = 0; traceIndex < trace_.size(); traceIndex++)
      std::fprintf(f, "%" PRIu32 ",%" PRIu32 "\n", traceIndex,
                   trace_[traceIndex].codeIndex);
    std::fclose(f);
    return 0;
  }

  int DumpUsesCsv(const char* path) const {
    std::FILE* f = std::fopen(path, "w");
    if (f == nullptr) return -errno;
    for (std::uint32_t traceIndex = 0; traceIndex < trace_.size();
         traceIndex++) {
      const InsnInTrace& trace = trace_[traceIndex];
      regState_.DumpUsesCsv(f, traceIndex, trace.regUseStartIndex,
                            trace.regUseEndIndex, trace_,
                            &InsnInTrace::regDefStartIndex, "r");
      memState_.DumpUsesCsv(f, traceIndex, trace.memUseStartIndex,
                            trace.memUseEndIndex, trace_,
                            &InsnInTrace::memDefStartIndex, "m");
    }
    std::fclose(f);
    return 0;
  }

  int DumpCsv() const {
    if (csv_ == nullptr) return 0;
    int ret;
    if ((ret = DumpCodeCsv(csvPath_.Get("code").c_str())) < 0) return ret;
    if ((ret = DumpTraceCsv(csvPath_.Get("trace").c_str())) < 0) return ret;
    if ((ret = DumpUsesCsv(csvPath_.Get("uses").c_str())) < 0) return ret;
    return 0;
  }

  int DumpBinary() const {
    if (binary_ == nullptr) return 0;
    std::FILE* f = std::fopen(binaryPath_.Get("header").c_str(), "wb");
    if (f == nullptr) return -errno;
    BinaryHeader header;
    *reinterpret_cast<std::uint16_t*>(header.magic) =
        ('M' << 8) | ('0' + sizeof(W));
    header.machineType = machineType_;
    header.endianness = endianness_;
    fwrite(&header, sizeof(header), 1, f);
    fclose(f);
    return 0;
  }

  const char* const dot_;
  const char* const html_;
  const char* const csv_;
  const char* const binary_;
  const bool verbose_;
  MachineType machineType_;
  Endianness endianness_;
  Disasm disasmEngine_;
  MmVector<InsnInCode<W>> code_;
  MmVector<std::uint8_t> text_;
  std::vector<std::string> disasm_;
  MmVector<InsnInTrace> trace_;
  UdState<W> regState_;
  UdState<W> memState_;
  PathWithPlaceholder csvPath_;
  PathWithPlaceholder binaryPath_;
};

int UdFile(const char* path, size_t start, size_t end, const char* dot,
           const char* html, const char* csv, const char* binary,
           bool verbose) {
  return VisitFile<Ud>(path, start, end, dot, html, csv, binary, verbose);
}

UdBase* UdBase::Load(const char* rawPath) {
  int err;
  PathWithPlaceholder path;
  if ((err = path.Init(rawPath, "binary")) < 0) return nullptr;
  BinaryHeader header;
  FILE* h = fopen(path.Get("header").c_str(), "r");
  if (h == nullptr) return nullptr;
  size_t n_read = fread(&header, sizeof(header), 1, h);
  fclose(h);
  if (n_read != 1) return nullptr;
  UdBase* ud = nullptr;
  switch (header.magic[0] << 8 | header.magic[1]) {
    case 'M' << 8 | '4':
      if (kHostEndianness == Endianness::Big)
        ud = new Ud<std::uint32_t>(nullptr, nullptr, nullptr, rawPath, false);
      break;
    case 'M' << 8 | '8':
      if (kHostEndianness == Endianness::Big)
        ud = new Ud<std::uint64_t>(nullptr, nullptr, nullptr, rawPath, false);
      break;
    case '4' << 8 | 'M':
      if (kHostEndianness == Endianness::Little)
        ud = new Ud<std::uint32_t>(nullptr, nullptr, nullptr, rawPath, false);
      break;
    case '8' << 8 | 'M':
      if (kHostEndianness == Endianness::Little)
        ud = new Ud<std::uint64_t>(nullptr, nullptr, nullptr, rawPath, false);
      break;
  }
  if (ud == nullptr) return nullptr;
  if (ud->Init(header) < 0) {
    delete ud;
    return nullptr;
  }
  return ud;
}

UdBase* UdBase::Analyze(TraceBase* trace) {
  UdBase* ud = nullptr;
  trace->Downcast([&ud](auto trace) {
    using Trace = typename std::remove_pointer<decltype(trace)>::type;
    typename Trace::ScopedRewind scopedRewind(trace);
    Ud<typename Trace::W>* udW =
        new Ud<typename Trace::W>(nullptr, nullptr, nullptr, nullptr, false);
    if (trace->Visit(udW) < 0) {
      delete udW;
      return;
    }
    ud = udW;
  });
  return ud;
}

template <Endianness E, typename W>
static std::string MangleName(const char* name) {
  return std::string(name) + GetEndiannessStr(E) +
         std::to_string(sizeof(W) * 8);
}

template <Endianness E, typename W>
void RegisterEntries() {
  namespace bp = boost::python;
  using LdStEntryPy = LdStEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<LdStEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("LdStEntry").c_str(), bp::no_init)
      .add_property("insn_seq", &LdStEntryPy::GetInsnSeq)
      .add_property("addr", &LdStEntryPy::GetAddr)
      .add_property("value", &LdStEntryPy::CopyValue);
  using InsnEntryPy = InsnEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<InsnEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("InsnEntry").c_str(), bp::no_init)
      .add_property("insn_seq", &InsnEntryPy::GetInsnSeq)
      .add_property("pc", &InsnEntryPy::GetPc)
      .add_property("value", &InsnEntryPy::CopyValue);
  using InsnExecEntryPy = InsnExecEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<InsnExecEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("InsnExecEntry").c_str(), bp::no_init)
      .add_property("insn_seq", &InsnExecEntryPy::GetInsnSeq);
  using LdStNxEntryPy = LdStNxEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<LdStNxEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("LdStNxEntry").c_str(), bp::no_init)
      .add_property("insn_seq", &LdStNxEntryPy::GetInsnSeq)
      .add_property("addr", &LdStNxEntryPy::GetAddr)
      .add_property("size", &LdStNxEntryPy::GetSize);
  using MmapEntryPy = MmapEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<MmapEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("MmapEntry").c_str(), bp::no_init)
      .add_property("start", &MmapEntryPy::GetStart)
      .add_property("end", &MmapEntryPy::GetEnd)
      .add_property("flags", &MmapEntryPy::GetFlags)
      .add_property("offset", &MmapEntryPy::GetOffset)
      .add_property("dev", &MmapEntryPy::GetDev)
      .add_property("inode", &MmapEntryPy::GetInode)
      .add_property("name", &MmapEntryPy::CopyValue);
}

}  // namespace

BOOST_PYTHON_MODULE(memtrace_ext) {
  namespace bp = boost::python;
  bp::enum_<Endianness>("Endianness")
      .value("Little", Endianness::Little)
      .value("Big", Endianness::Big);
  bp::def("get_endianness_str", GetEndiannessStrPy);
  bp::enum_<Tag>("Tag")
      .value("MT_LOAD", Tag::MT_LOAD)
      .value("MT_STORE", Tag::MT_STORE)
      .value("MT_REG", Tag::MT_REG)
      .value("MT_INSN", Tag::MT_INSN)
      .value("MT_GET_REG", Tag::MT_GET_REG)
      .value("MT_PUT_REG", Tag::MT_PUT_REG)
      .value("MT_INSN_EXEC", Tag::MT_INSN_EXEC)
      .value("MT_GET_REG_NX", Tag::MT_GET_REG_NX)
      .value("MT_PUT_REG_NX", Tag::MT_PUT_REG_NX)
      .value("MT_MMAP", Tag::MT_MMAP);
  bp::enum_<MachineType>("MachineType")
      .value("EM_386", MachineType::EM_386)
      .value("EM_X86_64", MachineType::EM_X86_64)
      .value("EM_PPC", MachineType::EM_PPC)
      .value("EM_PPC64", MachineType::EM_PPC64)
      .value("EM_ARM", MachineType::EM_ARM)
      .value("EM_AARCH64", MachineType::EM_AARCH64)
      .value("EM_S390", MachineType::EM_S390)
      .value("EM_MIPS", MachineType::EM_MIPS)
      .value("EM_NANOMIPS", MachineType::EM_NANOMIPS);
  bp::class_<EntryPy, boost::noncopyable>("Entry", bp::no_init)
      .def_readonly("index", &EntryPy::index)
      .add_property("tag", &EntryPy::GetTag);
  RegisterEntries<Endianness::Little, std::uint32_t>();
  RegisterEntries<Endianness::Little, std::uint64_t>();
  RegisterEntries<Endianness::Big, std::uint32_t>();
  RegisterEntries<Endianness::Big, std::uint64_t>();
  bp::def("dump_file", DumpFile);
  bp::class_<TagStats>("TagStats", bp::no_init)
      .def_readonly("count", &TagStats::count)
      .def_readonly("size", &TagStats::size);
  bp::class_<std::map<Tag, TagStats>>("std::map<Tag, TagStats>")
      .def(bp::map_indexing_suite<std::map<Tag, TagStats>>());
  bp::class_<Stats>("Stats", bp::no_init)
      .def_readonly("tag_stats", &Stats::tagStats);
  bp::class_<TraceBase, boost::noncopyable>("Trace", bp::no_init)
      .def("load", &TraceBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_endianness", &TraceBase::GetEndianness)
      .def("get_word_size", &TraceBase::GetWordSize)
      .def("get_machine_type", &TraceBase::GetMachineType)
      .def("get_regs_size", &TraceBase::GetRegsSize)
      .def("__iter__", bp::objects::identity_function())
      .def("__next__", &TraceBase::Next)
      .def("seek_insn", &TraceBase::SeekInsn)
      .def("gather_stats", &TraceBase::GatherStats)
      .def("build_insn_index", &TraceBase::BuildInsnIndex)
      .def("build_insn_index", &TraceBase::BuildInsnIndexDefault)
      .def("load_insn_index", &TraceBase::LoadInsnIndex)
      .def("get_mmap_entries", &TraceBase::GetMmapEntries);
  bp::def("ud_file", UdFile);
  bp::class_<std::vector<std::uint8_t>>("std::vector<std::uint8_t>")
      .def(bp::vector_indexing_suite<std::vector<std::uint8_t>>());
  bp::class_<std::vector<std::uint32_t>>("std::vector<std::uint32_t>")
      .def(bp::vector_indexing_suite<std::vector<std::uint32_t>>());
  bp::class_<UdBase, boost::noncopyable>("Ud", bp::no_init)
      .def("analyze", &UdBase::Analyze,
           bp::return_value_policy<bp::manage_new_object>())
      .def("load", &UdBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_codes_for_pc", &UdBase::GetCodesForPc)
      .def("get_pc_for_code", &UdBase::GetPcForCode)
      .def("get_disasm_for_code", &UdBase::GetDisasmForCode)
      .def("get_traces_for_code", &UdBase::GetTracesForCode)
      .def("get_code_for_trace", &UdBase::GetCodeForTrace)
      .def("get_reg_uses_for_trace", &UdBase::GetRegUsesForTrace)
      .def("get_mem_uses_for_trace", &UdBase::GetMemUsesForTrace)
      .def("get_trace_for_reg_use", &UdBase::GetTraceForRegUse)
      .def("get_trace_for_mem_use", &UdBase::GetTraceForMemUse);
  bp::class_<Disasm, boost::noncopyable>("Disasm", bp::no_init)
      .def("__init__", bp::make_constructor(CreateDisasm))
      .def("disasm_str", &Disasm::DisasmStr);
}
