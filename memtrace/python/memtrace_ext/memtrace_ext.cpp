// Copyright (C) 2019-2020, and GNU GPL'd, by mephi42.
#include <algorithm>
#include <array>
#include <cerrno>
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
#include <unordered_map>
#include <vector>

// clang-format off
#include <boost/python.hpp>
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
      return "<";
    case Endianness::Big:
      return ">";
    default:
      return nullptr;
  }
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define HostEndianness Endianness::Little
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HostEndianness Endianness::Big
#else
#error Unsupported __BYTE_ORDER__
#endif

class Buffer {
 public:
  Buffer() : low_(0), high_(0) {}

  int Update(std::istream* is) {
    size_t n = GetSize();
    memmove(storage_, storage_ + low_, n);
    is->read(reinterpret_cast<char*>(storage_ + n), sizeof(storage_) - n);
    low_ = 0;
    high_ = n + is->gcount();
    if (is->bad())
      return -EIO;
    else
      return 0;
  }

  void Advance(size_t n) { low_ += n; }

  const uint8_t* GetData() const { return storage_ + low_; }
  size_t GetSize() const { return high_ - low_; }

 private:
  uint8_t storage_[8192];
  size_t low_;
  size_t high_;
};

std::uint8_t BSwap(std::uint8_t value) { return value; }

std::uint16_t BSwap(std::uint16_t value) { return __builtin_bswap16(value); }

std::uint32_t BSwap(std::uint32_t value) { return __builtin_bswap32(value); }

std::uint64_t BSwap(std::uint64_t value) { return __builtin_bswap64(value); }

template <Endianness, typename T>
struct IntConversions {
  static T ConvertToHost(T value) { return BSwap(value); }
};

template <typename T>
struct IntConversions<HostEndianness, T> {
  static T ConvertToHost(T value) { return value; }
};

template <typename T, Endianness E, typename W>
class RawInt {
 public:
  explicit RawInt(const uint8_t* data) : data_(data) {}

  T GetValue() const {
    return IntConversions<E, T>::ConvertToHost(
        *reinterpret_cast<const T*>(data_));
  }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class Tlv {
 public:
  explicit Tlv(const uint8_t* data) : data_(data) {}

  Tag GetTag() const {
    return (Tag)RawInt<std::uint16_t, E, W>(data_).GetValue();
  }
  W GetLength() const {
    return RawInt<std::uint16_t, E, W>(data_ + 2).GetValue();
  }
  W GetAlignedLength() const {
    return (GetLength() + ((W)sizeof(W) - 1)) & ~((W)sizeof(W) - 1);
  }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class HeaderEntry {
 public:
  explicit HeaderEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  MachineType GetMachineType() const {
    return (MachineType)RawInt<std::uint16_t, E, W>(data_ + sizeof(W))
        .GetValue();
  }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class LdStEntry {
 public:
  explicit LdStEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<W, E, W>(data_ + sizeof(W)).GetValue(); }
  W GetAddr() const {
    return RawInt<W, E, W>(data_ + sizeof(W) * 2).GetValue();
  }
  const uint8_t* GetValue() const { return data_ + sizeof(W) * 3; }
  W GetSize() const { return GetTlv().GetLength() - (W)sizeof(W) * 3; }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class InsnEntry {
 public:
  explicit InsnEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<W, E, W>(data_ + sizeof(W)).GetValue(); }
  const uint8_t* GetValue() const { return data_ + sizeof(W) * 2; }
  W GetSize() const { return GetTlv().GetLength() - (W)sizeof(W) * 2; }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class InsnExecEntry {
 public:
  explicit InsnExecEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<W, E, W>(data_ + sizeof(W)).GetValue(); }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class LdStNxEntry {
 public:
  explicit LdStNxEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<W, E, W>(data_ + sizeof(W)).GetValue(); }
  W GetAddr() const {
    return RawInt<W, E, W>(data_ + sizeof(W) * 2).GetValue();
  }
  W GetSize() const {
    return RawInt<W, E, W>(data_ + sizeof(W) * 3).GetValue();
  }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W>
class MmapEntry {
 public:
  explicit MmapEntry(const uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetStart() const { return RawInt<W, E, W>(data_ + sizeof(W)).GetValue(); }
  W GetEnd() const { return RawInt<W, E, W>(data_ + sizeof(W) * 2).GetValue(); }
  W GetFlags() const {
    return RawInt<W, E, W>(data_ + sizeof(W) * 3).GetValue();
  }
  const uint8_t* GetValue() const { return data_ + sizeof(W) * 4; }
  W GetSize() const { return GetTlv().GetLength() - (W)sizeof(W) * 4; }

 private:
  const uint8_t* data_;
};

template <Endianness E, typename W, typename V>
int Parse(V* visitor, Buffer* buf, size_t* i, size_t start, size_t end) {
  while (buf->GetSize() >= 4) {
    Tlv<E, W> tlv(buf->GetData());
    if (buf->GetSize() < tlv.GetAlignedLength()) break;
    if (*i >= start && *i < end) {
      Tag tag = tlv.GetTag();
      int err;
      switch (tag) {
        case Tag::MT_LOAD:
        case Tag::MT_STORE:
        case Tag::MT_REG:
        case Tag::MT_GET_REG:
        case Tag::MT_PUT_REG:
          err = (*visitor)(*i, LdStEntry<E, W>(buf->GetData()));
          break;
        case Tag::MT_INSN:
          err = (*visitor)(*i, InsnEntry<E, W>(buf->GetData()));
          break;
        case Tag::MT_INSN_EXEC:
          err = (*visitor)(*i, InsnExecEntry<E, W>(buf->GetData()));
          break;
        case Tag::MT_GET_REG_NX:
        case Tag::MT_PUT_REG_NX:
          err = (*visitor)(*i, LdStNxEntry<E, W>(buf->GetData()));
          break;
        case Tag::MT_MMAP:
          err = (*visitor)(*i, MmapEntry<E, W>(buf->GetData()));
          break;
        default:
          std::cerr << "Unsupported tag: 0x" << std::hex << (std::uint16_t)tag
                    << std::endl;
          return -EINVAL;
      }
      if (err < 0) return err;
    }
    buf->Advance(tlv.GetAlignedLength());
    (*i)++;
  }
  return 0;
}

void HexDump(std::FILE* f, const uint8_t* buf, size_t n) {
  for (size_t i = 0; i < n; i++) std::fprintf(f, "%02x", buf[i]);
}

void ReprDump(const uint8_t* buf, size_t n) {
  std::printf("b'");
  for (size_t i = 0; i < n; i++) std::printf("\\x%02x", buf[i]);
  std::printf("'");
}

template <Endianness E, typename W>
void ValueDump(const uint8_t* buf, size_t n) {
  switch (n) {
    case 1:
      std::printf("0x%" PRIx8, RawInt<std::uint8_t, E, W>(buf).GetValue());
      break;
    case 2:
      std::printf("0x%" PRIx16, RawInt<std::uint16_t, E, W>(buf).GetValue());
      break;
    case 4:
      std::printf("0x%" PRIx32, RawInt<std::uint32_t, E, W>(buf).GetValue());
      break;
    case 8:
      std::printf("0x%" PRIx64, RawInt<std::uint64_t, E, W>(buf).GetValue());
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
  fprintf(f, "%s", escaped.c_str());
}

class CsFree {
 public:
  explicit CsFree(size_t count) : count_(count) {}

  void operator()(cs_insn* insn) { cs_free(insn, count_); }

 private:
  const size_t count_;
};

template <Endianness E, typename W>
class Disasm {
 public:
  Disasm() : capstone_(0) {}
  ~Disasm() {
    if (capstone_ != 0) cs_close(&capstone_);
  }

  int Init(MachineType type) {
    // See cstool.c for valid combinations.
    cs_arch arch;
    cs_mode mode;
    switch (type) {
      case MachineType::EM_386:
        if (E != Endianness::Little || sizeof(W) != 4) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
        break;
      case MachineType::EM_X86_64:
        if (E != Endianness::Little || sizeof(W) != 8) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
        break;
        // EM_PPC is not supported.
      case MachineType::EM_PPC64:
        if (sizeof(W) != 8) return -EINVAL;
        arch = CS_ARCH_PPC;
        if (E == Endianness::Little)
          mode = (cs_mode)(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
        else
          mode = (cs_mode)(CS_MODE_64 | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::EM_ARM:
        if (sizeof(W) != 4) return -EINVAL;
        arch = CS_ARCH_ARM;
        if (E == Endianness::Little)
          mode = (cs_mode)(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
        else
          mode = (cs_mode)(CS_MODE_ARM | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::EM_AARCH64:
        if (sizeof(W) != 8) return -EINVAL;
        arch = CS_ARCH_ARM64;
        if (E == Endianness::Little)
          mode = CS_MODE_LITTLE_ENDIAN;
        else
          mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::EM_S390:
        if (E != Endianness::Big) return -EINVAL;
        arch = CS_ARCH_SYSZ;
        mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::EM_MIPS:
        arch = CS_ARCH_MIPS;
        if (sizeof(W) == 4) {
          if (E == Endianness::Little)
            mode = (cs_mode)(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN);
          else
            mode = (cs_mode)(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN);
        } else {
          if (E == Endianness::Little)
            mode = (cs_mode)(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN);
          else
            mode = (cs_mode)(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN);
        }
        break;
        // EM_NANOMIPS is not supported.
      default:
        return -1;
    }
    if (cs_open(arch, mode, &capstone_) != CS_ERR_OK) return -1;
    return 0;
  }

  std::unique_ptr<cs_insn, CsFree> DoDisasm(const uint8_t* code,
                                            size_t codeSize, uint64_t address,
                                            size_t count) {
    cs_insn* insn = nullptr;
    size_t actualCount =
        cs_disasm(capstone_, code, codeSize, address, count, &insn);
    return std::unique_ptr<cs_insn, CsFree>(insn, CsFree(actualCount));
  }

 private:
  csh capstone_;
};

template <Endianness E, typename W>
class Dumper {
 public:
  Dumper() : insnCount_(0) {}

  int Init(HeaderEntry<E, W> entry, size_t /* expectedInsnCount */) {
    std::printf("Endian            : %s\n", GetEndiannessStr(E));
    std::printf("Word              : %s\n", sizeof(W) == 4 ? "I" : "Q");
    std::printf("Word size         : %zu\n", sizeof(W));
    std::printf("Machine           : %s\n",
                GetMachineTypeStr(entry.GetMachineType()));
    return disasm_.Init(entry.GetMachineType());
  }

  int operator()(size_t i, LdStEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s uint%zu_t [0x%" PRIx64 "] ", i,
                (std::uint64_t)entry.GetPc(),
                GetTagStr(entry.GetTlv().GetTag()),
                (size_t)(entry.GetSize() * 8), (std::uint64_t)entry.GetAddr());
    ValueDump<E, W>(entry.GetValue(), entry.GetSize());
    std::printf("\n");
    return 0;
  }

  int operator()(size_t i, InsnEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s ", i,
                (std::uint64_t)entry.GetPc(),
                GetTagStr(entry.GetTlv().GetTag()));
    HexDump(stdout, entry.GetValue(), entry.GetSize());
    std::unique_ptr<cs_insn, CsFree> insn =
        disasm_.DoDisasm(entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
    if (insn)
      std::printf(" %s %s\n", insn->mnemonic, insn->op_str);
    else
      std::printf(" <unknown>\n");
    return 0;
  }

  int operator()(size_t i, InsnExecEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s\n", i,
                (std::uint64_t)entry.GetPc(),
                GetTagStr(entry.GetTlv().GetTag()));
    insnCount_++;
    return 0;
  }

  int operator()(size_t i, LdStNxEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s uint%zu_t [0x%" PRIx64 "]\n", i,
                (std::uint64_t)entry.GetPc(),
                GetTagStr(entry.GetTlv().GetTag()),
                (size_t)(entry.GetSize() * 8), (std::uint64_t)entry.GetAddr());
    return 0;
  }

  int operator()(size_t i, MmapEntry<E, W> entry) {
    std::printf(
        "[%10zu] %016" PRIx64 "-%016" PRIx64 " %c%c%c %s\n", i,
        (std::uint64_t)entry.GetStart(), (std::uint64_t)(entry.GetEnd() + 1),
        entry.GetFlags() & 1 ? 'r' : '-', entry.GetFlags() & 2 ? 'w' : '-',
        entry.GetFlags() & 4 ? 'x' : '-', entry.GetValue());
    return 0;
  }

  int Complete() {
    std::printf("Insns             : %zu\n", insnCount_);
    return 0;
  }

 private:
  size_t insnCount_;
  Disasm<E, W> disasm_;
};

template <Endianness E, typename W, template <Endianness, typename> typename V,
          typename... Args>
int Rest(std::istream* is, size_t expectedInsnCount, Buffer* buf, size_t start,
         size_t end, Args&&... args) {
  HeaderEntry<E, W> entry(buf->GetData());
  buf->Advance(entry.GetTlv().GetAlignedLength());
  V<E, W> visitor(std::forward<Args>(args)...);
  if (visitor.Init(entry, expectedInsnCount) < 0) {
    std::cerr << "visitor.Init() failed" << std::endl;
    return EXIT_FAILURE;
  }
  size_t i = 0;
  while (buf->GetSize() > 0) {
    if (Parse<E, W>(&visitor, buf, &i, start, end) < 0) {
      std::cerr << "Parse(buf) failed" << std::endl;
      return EXIT_FAILURE;
    }
    if (buf->Update(is) < 0) {
      std::cerr << "buf.Update() failed" << std::endl;
      return EXIT_FAILURE;
    }
  }
  if (visitor.Complete() < 0) {
    std::cerr << "visitor.Complete() failed" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

template <template <Endianness, typename> typename V, typename... Args>
int VisitFile(const char* path, size_t start, size_t end, Args&&... args) {
  std::ifstream is(path, std::ios::binary | std::ios::ate);
  if (!is) {
    std::cerr << "Could not open " << path << std::endl;
    return EXIT_FAILURE;
  }
  size_t size = is.tellg();
  // On average, one executed instruction takes 132.7 bytes in the trace file.
  size_t expectedInsnCount = size / 128;
  is.seekg(0, std::ios::beg);
  Buffer buf;
  if (buf.Update(&is) < 0 || buf.GetSize() < 2) {
    std::cerr << "buf.Update() failed" << std::endl;
    return EXIT_FAILURE;
  }
  if (buf.GetData()[0] == 'M' && buf.GetData()[1] == '4') {
    return Rest<Endianness::Big, std::uint32_t, V>(
        &is, expectedInsnCount, &buf, start, end, std::forward<Args>(args)...);
  } else if (buf.GetData()[0] == 'M' && buf.GetData()[1] == '8') {
    return Rest<Endianness::Big, std::uint64_t, V>(
        &is, expectedInsnCount, &buf, start, end, std::forward<Args>(args)...);
  } else if (buf.GetData()[0] == '4' && buf.GetData()[1] == 'M') {
    return Rest<Endianness::Little, std::uint32_t, V>(
        &is, expectedInsnCount, &buf, start, end, std::forward<Args>(args)...);
  } else if (buf.GetData()[0] == '8' && buf.GetData()[1] == 'M') {
    return Rest<Endianness::Little, std::uint64_t, V>(
        &is, expectedInsnCount, &buf, start, end, std::forward<Args>(args)...);
  } else {
    std::cerr << "Unsupported magic" << std::endl;
    return EXIT_FAILURE;
  }
}

int DumpFile(const char* path, size_t start, size_t end) {
  return VisitFile<Dumper>(path, start, end);
}

template <typename W>
struct Def {
  W startAddr;
  W endAddr;
};

template <typename W>
struct InsnInCode {
  W pc;
  std::unique_ptr<std::uint8_t[]> raw;
  size_t rawSize;
  std::string disasm;
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

template <typename W>
class UdState {
 public:
  void Init(size_t expectedUseCount, size_t expectedDefCount) {
    uses_.reserve(expectedUseCount);
    defs_.reserve(expectedDefCount);
    AddDef(0, std::numeric_limits<W>::max());
  }

  void AddUses(W startAddr, W size) {
    W endAddr = startAddr + size;
    for (It it = addressSpace_.lower_bound(startAddr + 1);
         it != addressSpace_.end() && it->second.startAddr < endAddr; ++it) {
      std::uint32_t useIndex = (std::uint32_t)uses_.size();
      uses_.push_back(it->second.defIndex);
      const Def<W>& def = defs_[it->second.defIndex];
      W maxStartAddr = std::max(startAddr, it->second.startAddr);
      W minEndAddr = std::min(endAddr, it->first);
      if (def.startAddr != maxStartAddr || def.endAddr != minEndAddr)
        partialUses_[useIndex] = Def<W>{maxStartAddr, minEndAddr};
    }
  }

  int AddDefs(W startAddr, W size) {
    W endAddr = startAddr + size;
    It firstAffected = addressSpace_.lower_bound(startAddr + 1);
    It lastAffected;
    std::uint32_t affectedCount;
    for (lastAffected = firstAffected, affectedCount = 0;
         lastAffected != addressSpace_.end() &&
         lastAffected->second.startAddr < endAddr;
         ++lastAffected, affectedCount++) {
    }
    // sizeofIRType() maximum return value is 32, so affectedCount <= 32.
    constexpr std::uint32_t kMaxAffectedCount = 32;
    if (affectedCount > kMaxAffectedCount) return -EINVAL;
    std::array<Entry, kMaxAffectedCount> affected;
    std::copy(firstAffected, lastAffected, affected.begin());
    addressSpace_.erase(firstAffected, lastAffected);
    for (std::uint32_t affectedIndex = 0; affectedIndex < affectedCount;
         affectedIndex++) {
      const Entry& entry = affected[affectedIndex];
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

  void DumpUses(std::uint32_t startIndex, std::uint32_t endIndex,
                const std::vector<InsnInTrace>& trace,
                std::uint32_t InsnInTrace::*startIndexMember) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startIndexMember);
      std::printf(useIndex == startIndex
                      ? "0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]"
                      : ", 0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]",
                  (std::uint64_t)use.first->startAddr,
                  (std::uint64_t)use.first->endAddr, use.second);
    }
  }

  void DumpDefs(std::uint32_t startIndex, std::uint32_t endIndex) const {
    for (std::uint32_t defIndex = startIndex; defIndex < endIndex; defIndex++)
      std::printf(defIndex == startIndex ? "0x%" PRIx64 "-0x%" PRIx64
                                         : ", 0x%" PRIx64 "-0x%" PRIx64,
                  (std::uint64_t)defs_[defIndex].startAddr,
                  (std::uint64_t)defs_[defIndex].endAddr);
  }

  void DumpUsesDot(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const std::vector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startIndexMember,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startIndexMember);
      fprintf(f,
              "    %" PRIu32 " -> %" PRIu32 " [label=\"%s0x%" PRIx64
              "-0x%" PRIx64 "\"]\n",
              traceIndex, use.second, prefix,
              (std::uint64_t)use.first->startAddr,
              (std::uint64_t)use.first->endAddr);
    }
  }

  void DumpUsesHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex,
                    const std::vector<InsnInTrace>& trace,
                    std::uint32_t InsnInTrace::*startIndexMember,
                    const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startIndexMember);
      fprintf(f,
              "            <a href=\"#%" PRIu32 "\">%s0x%" PRIx64 "-0x%" PRIx64
              "</a>\n",
              use.second, prefix, (std::uint64_t)use.first->startAddr,
              (std::uint64_t)use.first->endAddr);
    }
  }

  void DumpDefsHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex, const char* prefix) const {
    for (std::uint32_t i = startIndex; i < endIndex; i++)
      std::fprintf(f, "            %s0x%" PRIx64 "-0x%" PRIx64 "\n", prefix,
                   (std::uint64_t)defs_[i].startAddr,
                   (std::uint64_t)defs_[i].endAddr);
  }

  void DumpUsesCsv(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const std::vector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startIndexMember,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startIndexMember);
      fprintf(f, "%" PRIu32 ",%" PRIu32 ",%s,%" PRIu64 ",%" PRIu64 "\n",
              traceIndex, use.second, prefix,
              (std::uint64_t)use.first->startAddr,
              (std::uint64_t)use.first->endAddr);
    }
  }

 private:
  void AddDef(W startAddr, W endAddr) {
    std::uint32_t defIndex = (std::uint32_t)defs_.size();
    Def<W>& def = defs_.emplace_back();
    def.startAddr = startAddr;
    def.endAddr = endAddr;
    addressSpace_[endAddr] = EntryValue{startAddr, defIndex};
  }

  std::pair<const Def<W>*, std::uint32_t> ResolveUse(
      std::uint32_t useIndex, const std::vector<InsnInTrace>& trace,
      std::uint32_t InsnInTrace::*startIndexMember) const {
    std::uint32_t defIndex = uses_[useIndex];
    const Def<W>* def;
    typename std::unordered_map<std::uint32_t, Def<W>>::const_iterator
        partialUse = partialUses_.find(useIndex);
    if (partialUse == partialUses_.end())
      def = &defs_[defIndex];
    else
      def = &partialUse->second;

    std::vector<InsnInTrace>::const_iterator it =
        std::upper_bound(trace.begin(), trace.end(), defIndex,
                         [startIndexMember](std::uint32_t defIndex,
                                            const InsnInTrace& trace) -> bool {
                           return defIndex < trace.*startIndexMember;
                         });
    --it;
    std::uint32_t traceIndex = (std::uint32_t)(it - trace.begin());

    return std::make_pair(def, traceIndex);
  }

  std::vector<std::uint32_t> uses_;  // defs_ indices.
  // The assumption is that partial uses are rare.
  // uses_ index -> range.
  std::unordered_map<std::uint32_t, Def<W>> partialUses_;
  std::vector<Def<W>> defs_;
  struct EntryValue {
    W startAddr;
    std::uint32_t defIndex;
  };
  // endAddr -> EntryValue.
  using AddressSpace = typename std::map<W, EntryValue>;
  using Entry = typename std::pair<W, EntryValue>;
  using It = typename AddressSpace::const_iterator;
  AddressSpace addressSpace_;
};

const char kCsvPlaceholder[] = "{}";
constexpr size_t kCsvPlaceholderLength = sizeof(kCsvPlaceholder) - 1;

template <Endianness E, typename W>
class Ud {
 public:
  Ud(const char* dot, const char* html, const char* csv, bool verbose)
      : dot_(dot), html_(html), csv_(csv), verbose_(verbose) {}

  int Init(HeaderEntry<E, W> entry, size_t expectedInsnCount) {
    if (csv_ != nullptr) {
      csvPlaceholder_ = std::strstr(csv_, kCsvPlaceholder);
      if (csvPlaceholder_ == nullptr) {
        std::cerr << "csv path must contain a " << kCsvPlaceholder
                  << " placeholder" << std::endl;
        return -EINVAL;
      }
    }

    trace_.reserve(expectedInsnCount);

    std::uint32_t codeIndex = (std::uint32_t)code_.size();
    InsnInCode<W>& code = code_.emplace_back();
    code.pc = 0;
    code.rawSize = 0;
    code.disasm = "<unknown>";

    AddTrace(codeIndex);
    // On average, 1.48 register uses and 1.61 register defs per insn.
    regState_.Init(expectedInsnCount * 3 / 2, expectedInsnCount * 5 / 3);
    // On average, 0.4 memory uses and 0.22 memory defs per insn.
    memState_.Init(expectedInsnCount / 2, expectedInsnCount / 4);

    return disasm_.Init(entry.GetMachineType());
  }

  int operator()(size_t /* i */, LdStEntry<E, W> entry) {
    int ret;
    if ((ret = HandlePc(entry.GetPc())) < 0) return ret;
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

  int operator()(size_t /* i */, InsnEntry<E, W> entry) {
    pcs_[entry.GetPc()] = (std::uint32_t)code_.size();
    InsnInCode<W>& code = code_.emplace_back();
    code.pc = entry.GetPc();
    code.raw.reset(new uint8_t[entry.GetSize()]);
    std::memcpy(code.raw.get(), entry.GetValue(), entry.GetSize());
    code.rawSize = entry.GetSize();
    std::unique_ptr<cs_insn, CsFree> insn =
        disasm_.DoDisasm(entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
    if (insn) {
      code.disasm = insn->mnemonic;
      code.disasm += " ";
      code.disasm += insn->op_str;
    } else {
      code.disasm = "<unknown>";
    }
    return 0;
  }

  int operator()(size_t /* i */, InsnExecEntry<E, W> entry) {
    int ret;
    if ((ret = HandlePc(entry.GetPc())) < 0) return ret;
    return 0;
  }

  int operator()(size_t /* i */, LdStNxEntry<E, W> entry) {
    int ret;
    if ((ret = HandlePc(entry.GetPc())) < 0) return ret;
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

  int operator()(size_t /* i */, MmapEntry<E, W> /* entry */) { return 0; }

  int Complete() {
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = DumpDot()) < 0) return ret;
    if ((ret = DumpHtml()) < 0) return ret;
    if ((ret = DumpCsv()) < 0) return ret;
    return 0;
  }

 private:
  int Flush() {
    InsnInTrace& trace = trace_.back();
    trace.regUseEndIndex = (std::uint32_t)regState_.GetUseCount();
    trace.memUseEndIndex = (std::uint32_t)memState_.GetUseCount();
    trace.regDefEndIndex = (std::uint32_t)regState_.GetDefCount();
    trace.memDefEndIndex = (std::uint32_t)memState_.GetDefCount();

    if (verbose_) {
      InsnInCode<W>& code = code_[trace.codeIndex];
      std::printf("[%zu]0x%" PRIx64 ": ", trace_.size() - 1,
                  (std::uint64_t)code.pc);
      HexDump(stdout, code.raw.get(), code.rawSize);
      std::printf(" %s reg_uses=[", code.disasm.c_str());
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
    trace.regUseStartIndex = (std::uint32_t)regState_.GetUseCount();
    trace.memUseStartIndex = (std::uint32_t)memState_.GetUseCount();
    trace.regDefStartIndex = (std::uint32_t)regState_.GetDefCount();
    trace.memDefStartIndex = (std::uint32_t)memState_.GetDefCount();
    return 0;
  }

  int HandlePc(W pc) {
    if (code_[trace_.back().codeIndex].pc == pc) return 0;
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = AddTrace(pcs_[pc])) < 0) return ret;
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
          traceIndex, traceIndex, (std::uint64_t)code.pc, code.disasm.c_str());
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
                   traceIndex, traceIndex, (std::uint64_t)code.pc);
      HexDump(f, code.raw.get(), code.rawSize);
      std::fprintf(f,
                   "</td>\n"
                   "        <td>");
      HtmlDump(f, code.disasm.c_str());
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
      std::fprintf(f, "%" PRIu32 ",%" PRIu64 ",", codeIndex,
                   (std::uint64_t)code_[codeIndex].pc);
      HexDump(f, code_[codeIndex].raw.get(), code_[codeIndex].rawSize);
      std::fprintf(f, ",\"%s\"\n", code_[codeIndex].disasm.c_str());
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
    size_t prefixLength = csvPlaceholder_ - csv_;
    const char* suffix = csvPlaceholder_ + kCsvPlaceholderLength;
    std::string codeCsvPath(csv_, prefixLength);
    codeCsvPath += "code";
    codeCsvPath += suffix;
    std::string traceCsvPath(csv_, prefixLength);
    traceCsvPath += "trace";
    traceCsvPath += suffix;
    std::string usesCsvPath(csv_, prefixLength);
    usesCsvPath += "uses";
    usesCsvPath += suffix;
    int ret;
    if ((ret = DumpCodeCsv(codeCsvPath.c_str())) < 0) return ret;
    if ((ret = DumpTraceCsv(traceCsvPath.c_str())) < 0) return ret;
    if ((ret = DumpUsesCsv(usesCsvPath.c_str())) < 0) return ret;
    return 0;
  }

  const char* const dot_;
  const char* const html_;
  const char* const csv_;
  const bool verbose_;
  const char* csvPlaceholder_;
  Disasm<E, W> disasm_;
  std::vector<InsnInCode<W>> code_;
  std::unordered_map<W, std::uint32_t> pcs_;
  std::vector<InsnInTrace> trace_;
  UdState<W> regState_;
  UdState<W> memState_;
};

int UdFile(const char* path, size_t start, size_t end, const char* dot,
           const char* html, const char* csv, bool verbose) {
  return VisitFile<Ud>(path, start, end, dot, html, csv, verbose);
}

}  // namespace

BOOST_PYTHON_MODULE(memtrace_ext) {
  boost::python::def("dump_file", DumpFile);
  boost::python::def("ud_file", UdFile);
}
