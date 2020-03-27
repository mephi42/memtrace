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
#include <unordered_map>
#include <vector>

// clang-format off
#include <boost/python.hpp>
#include <boost/python/object/iterator_core.hpp>
#include <boost/python/scope.hpp>
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

template <Endianness E, typename T>
class RawInt {
 public:
  explicit RawInt(const std::uint8_t* data) : data_(data) {}

  T GetValue() const {
    return IntConversions<E, T>::ConvertToHost(
        *reinterpret_cast<const T*>(data_));
  }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class Tlv {
 public:
  explicit Tlv(const std::uint8_t* data) : data_(data) {}

  static size_t GetFixedLength() { return sizeof(std::uint16_t) * 2; }

  Tag GetTag() const {
    return static_cast<Tag>(RawInt<E, std::uint16_t>(data_).GetValue());
  }
  W GetLength() const { return RawInt<E, std::uint16_t>(data_ + 2).GetValue(); }
  W GetAlignedLength() const {
    return (GetLength() + (static_cast<W>(sizeof(W)) - 1)) &
           ~(static_cast<W>(sizeof(W)) - 1);
  }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class HeaderEntry {
 public:
  explicit HeaderEntry(const std::uint8_t* data) : data_(data) {}

  static size_t GetFixedLength() { return sizeof(W) + sizeof(std::uint16_t); }

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  MachineType GetMachineType() const {
    return static_cast<MachineType>(
        RawInt<E, std::uint16_t>(data_ + sizeof(W)).GetValue());
  }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class LdStEntry {
 public:
  explicit LdStEntry(const std::uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<E, W>(data_ + sizeof(W)).GetValue(); }
  W GetAddr() const { return RawInt<E, W>(data_ + sizeof(W) * 2).GetValue(); }
  const std::uint8_t* GetValue() const { return data_ + sizeof(W) * 3; }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(sizeof(W)) * 3;
  }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class InsnEntry {
 public:
  explicit InsnEntry(const std::uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<E, W>(data_ + sizeof(W)).GetValue(); }
  const std::uint8_t* GetValue() const { return data_ + sizeof(W) * 2; }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(sizeof(W)) * 2;
  }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class InsnExecEntry {
 public:
  explicit InsnExecEntry(const std::uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<E, W>(data_ + sizeof(W)).GetValue(); }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class LdStNxEntry {
 public:
  explicit LdStNxEntry(const std::uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetPc() const { return RawInt<E, W>(data_ + sizeof(W)).GetValue(); }
  W GetAddr() const { return RawInt<E, W>(data_ + sizeof(W) * 2).GetValue(); }
  W GetSize() const { return RawInt<E, W>(data_ + sizeof(W) * 3).GetValue(); }

 private:
  const std::uint8_t* data_;
};

template <Endianness E, typename W>
class MmapEntry {
 public:
  explicit MmapEntry(const std::uint8_t* data) : data_(data) {}

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(data_); }
  W GetStart() const { return RawInt<E, W>(data_ + sizeof(W)).GetValue(); }
  W GetEnd() const { return RawInt<E, W>(data_ + sizeof(W) * 2).GetValue(); }
  W GetFlags() const { return RawInt<E, W>(data_ + sizeof(W) * 3).GetValue(); }
  const std::uint8_t* GetValue() const { return data_ + sizeof(W) * 4; }
  W GetSize() const {
    return GetTlv().GetLength() - static_cast<W>(sizeof(W)) * 4;
  }

 private:
  const std::uint8_t* data_;
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
    return disasmEngine_.Init(entry.GetMachineType(), E, sizeof(W));
  }

  int operator()(size_t i, LdStEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s uint%zu_t [0x%" PRIx64 "] ", i,
                static_cast<std::uint64_t>(entry.GetPc()),
                GetTagStr(entry.GetTlv().GetTag()),
                static_cast<size_t>(entry.GetSize() * 8),
                static_cast<std::uint64_t>(entry.GetAddr()));
    ValueDump<E>(entry.GetValue(), entry.GetSize());
    std::printf("\n");
    return 0;
  }

  int operator()(size_t i, InsnEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s ", i,
                static_cast<std::uint64_t>(entry.GetPc()),
                GetTagStr(entry.GetTlv().GetTag()));
    HexDump(stdout, entry.GetValue(), entry.GetSize());
    std::unique_ptr<cs_insn, CsFree> insn = disasmEngine_.DoDisasm(
        entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
    if (insn)
      std::printf(" %s %s\n", insn->mnemonic, insn->op_str);
    else
      std::printf(" <unknown>\n");
    return 0;
  }

  int operator()(size_t i, InsnExecEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s\n", i,
                static_cast<std::uint64_t>(entry.GetPc()),
                GetTagStr(entry.GetTlv().GetTag()));
    insnCount_++;
    return 0;
  }

  int operator()(size_t i, LdStNxEntry<E, W> entry) {
    std::printf("[%10zu] 0x%016" PRIx64 ": %s uint%zu_t [0x%" PRIx64 "]\n", i,
                static_cast<std::uint64_t>(entry.GetPc()),
                GetTagStr(entry.GetTlv().GetTag()),
                static_cast<size_t>(entry.GetSize() * 8),
                static_cast<std::uint64_t>(entry.GetAddr()));
    return 0;
  }

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

class TraceMmBase {
 public:
  template <typename V>
  static int Visit(const char* path, const V& v);
  static TraceMmBase* Load(const char* path);

  virtual ~TraceMmBase() = default;
  virtual Endianness GetEndianness() = 0;
  virtual size_t GetWordSize() = 0;
  virtual MachineType GetMachineType() = 0;
  virtual boost::python::object Next() = 0;
  virtual void SeekInsn(std::uint32_t index) = 0;
};

struct EntryPy {
  template <Endianness E, typename W>
  EntryPy(size_t index, Tlv<E, W> tlv) : index(index), tag(tlv.GetTag()) {}
  virtual ~EntryPy() = default;

  std::uint64_t index;
  Tag tag;
};

struct LdStEntryPy : public EntryPy {
  template <Endianness E, typename W>
  LdStEntryPy(size_t index, LdStEntry<E, W> entry)
      : EntryPy(index, entry.GetTlv()),
        pc(entry.GetPc()),
        addr(entry.GetAddr()),
        value(entry.GetValue(), entry.GetValue() + entry.GetSize()) {}

  std::uint64_t pc;
  std::uint64_t addr;
  std::vector<std::uint8_t> value;
};

struct InsnEntryPy : public EntryPy {
  template <Endianness E, typename W>
  InsnEntryPy(size_t index, const InsnEntry<E, W>& entry)
      : EntryPy(index, entry.GetTlv()),
        pc(entry.GetPc()),
        value(entry.GetValue(), entry.GetValue() + entry.GetSize()) {}

  std::uint64_t pc;
  std::vector<std::uint8_t> value;
};

struct InsnExecEntryPy : public EntryPy {
  template <Endianness E, typename W>
  InsnExecEntryPy(size_t index, const InsnExecEntry<E, W>& entry)
      : EntryPy(index, entry.GetTlv()), pc(entry.GetPc()) {}

  std::uint64_t pc;
};

struct LdStNxEntryPy : public EntryPy {
  template <Endianness E, typename W>
  LdStNxEntryPy(size_t index, const LdStNxEntry<E, W>& entry)
      : EntryPy(index, entry.GetTlv()),
        pc(entry.GetPc()),
        addr(entry.GetAddr()),
        size(entry.GetSize()) {}

  std::uint64_t pc;
  std::uint64_t addr;
  std::uint64_t size;
};

struct MmapEntryPy : public EntryPy {
  template <Endianness E, typename W>
  MmapEntryPy(size_t index, const MmapEntry<E, W>& entry)
      : EntryPy(index, entry.GetTlv()),
        start(entry.GetStart()),
        end(entry.GetEnd()),
        flags(entry.GetFlags()),
        name(reinterpret_cast<const char*>(entry.GetValue())) {}

  std::uint64_t start;
  std::uint64_t end;
  std::uint64_t flags;
  std::string name;
};

template <Endianness E, typename W>
struct TraceEntry2Py {
  int operator()(size_t index, LdStEntry<E, W> entry) {
    py = boost::python::object(new LdStEntryPy(index, entry));
    return 0;
  }

  int operator()(size_t index, InsnEntry<E, W> entry) {
    py = boost::python::object(new InsnEntryPy(index, entry));
    return 0;
  }

  int operator()(size_t index, InsnExecEntry<E, W> entry) {
    py = boost::python::object(new InsnExecEntryPy(index, entry));
    return 0;
  }

  int operator()(size_t index, LdStNxEntry<E, W> entry) {
    py = boost::python::object(new LdStNxEntryPy(index, entry));
    return 0;
  }

  int operator()(size_t index, MmapEntry<E, W> entry) {
    py = boost::python::object(new MmapEntryPy(index, entry));
    return 0;
  }

  boost::python::object py;
};

template <Endianness E, typename W>
struct Seek {
  Seek()
      : insnIndex(std::numeric_limits<size_t>::max()),
        prevPc(std::numeric_limits<W>::max()) {}

  int operator()(size_t /* index */, LdStEntry<E, W> entry) {
    return HandlePc(entry.GetPc());
  }

  int operator()(size_t /* index */, InsnEntry<E, W> /* entry */) { return 0; }

  int operator()(size_t /* index */, InsnExecEntry<E, W> entry) {
    return HandlePc(entry.GetPc());
  }

  int operator()(size_t /* index */, LdStNxEntry<E, W> entry) {
    return HandlePc(entry.GetPc());
  }

  int operator()(size_t /* index */, MmapEntry<E, W> /* entry */) { return 0; }

  int HandlePc(W pc) {
    if (pc != prevPc) {
      insnIndex++;
      prevPc = pc;
    }
    return 0;
  }

  size_t insnIndex;
  W prevPc;
};

template <Endianness E, typename W>
class TraceMm : public TraceMmBase {
 public:
  TraceMm(void* data, size_t length)
      : data_(data),
        length_(length),
        cur_(static_cast<std::uint8_t*>(data_)),
        end_(cur_ + length_),
        entryIndex_(0),
        header_(cur_) {}
  virtual ~TraceMm() { munmap(data_, length_); }

  template <typename V>
  static int CreateAndVisit(std::uint8_t* data, size_t length, const V& v) {
    int err;
    TraceMm<E, W>* trace = new TraceMm<E, W>(data, length);
    if ((err = trace->Init()) < 0) {
      delete trace;
      return err;
    }
    return v(trace);
  }

  int Init() {
    if (!Have(HeaderEntry<E, W>::GetFixedLength())) return -EINVAL;
    if (!Advance(header_.GetTlv().GetAlignedLength())) return -EINVAL;
    return 0;
  }

  template <template <Endianness, typename> typename V, typename... Args>
  int Visit(size_t start, size_t end, Args&&... args) {
    V<E, W> visitor(std::forward<Args>(args)...);
    // On average, one executed instruction takes 132.7 bytes in the trace file.
    int err;
    if ((err = visitor.Init(header_, length_ / 128)) < 0) return err;
    while (cur_ != end_)
      if ((err = VisitOne(start, end, &visitor)) < 0) return err;
    if ((err = visitor.Complete()) < 0) return err;
    return 0;
  }

  template <typename V>
  int VisitOne(size_t start, size_t end, V* visitor) {
    if (!Have(Tlv<E, W>::GetFixedLength())) return -EINVAL;
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

  boost::python::object Next() override {
    if (cur_ == end_) boost::python::objects::stop_iteration_error();
    TraceEntry2Py<E, W> visitor;
    int err = VisitOne(std::numeric_limits<size_t>::min(),
                       std::numeric_limits<size_t>::max(), &visitor);
    if (err < 0) throw std::runtime_error("Failed to parse the next entry");
    return visitor.py;
  }

  void SeekInsn(std::uint32_t index) override {
    cur_ =
        static_cast<std::uint8_t*>(data_) + header_.GetTlv().GetAlignedLength();
    entryIndex_ = 0;
    Seek<E, W> visitor;
    while (true) {
      if (cur_ == end_) throw std::invalid_argument("No such insn");
      std::uint8_t* prev = cur_;
      int err = VisitOne(std::numeric_limits<size_t>::min(),
                         std::numeric_limits<size_t>::max(), &visitor);
      if (err < 0) throw std::runtime_error("Failed to parse the next entry");
      if (visitor.insnIndex == index) {
        cur_ = prev;
        entryIndex_--;
        break;
      }
    }
  }

 private:
  bool Have(size_t n) const { return cur_ + n <= end_; }

  bool Advance(size_t n) {
    std::uint8_t* next = cur_ + n;
    if (next > end_) return false;
    cur_ = next;
    return true;
  }

  void* data_;
  size_t length_;
  std::uint8_t* cur_;
  std::uint8_t* end_;
  size_t entryIndex_;
  HeaderEntry<E, W> header_;
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
int TraceMmBase::Visit(const char* path, const V& v) {
  int err;
  std::uint8_t* data;
  size_t length;
  if ((err = MmapFile(path, 2, &data, &length)) < 0) return err;
  if (data == MAP_FAILED) return -ENOMEM;
  switch (data[0] << 8 | data[1]) {
    case 'M' << 8 | '4':
      return TraceMm<Endianness::Big, std::uint32_t>::CreateAndVisit(data,
                                                                     length, v);
    case 'M' << 8 | '8':
      return TraceMm<Endianness::Big, std::uint64_t>::CreateAndVisit(data,
                                                                     length, v);
    case '4' << 8 | 'M':
      return TraceMm<Endianness::Little, std::uint32_t>::CreateAndVisit(
          data, length, v);
    case '8' << 8 | 'M':
      return TraceMm<Endianness::Little, std::uint64_t>::CreateAndVisit(
          data, length, v);
    default:
      munmap(data, length);
      return -EINVAL;
  }
}

template <template <Endianness, typename> typename V, typename... Args>
int VisitFile(const char* path, size_t start, size_t end, Args&&... args) {
  return TraceMmBase::Visit(path, [start, end, &args...](auto trace) {
    int err = trace->template Visit<V>(start, end, std::forward<Args>(args)...);
    delete trace;
    return err;
  });
}

TraceMmBase* TraceMmBase::Load(const char* path) {
  TraceMmBase* result = nullptr;
  Visit(path, [&result](TraceMmBase* trace) -> int {
    result = trace;
    return 0;
  });
  return result;
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
  Def<W> second;        // range
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
  explicit PartialUses(size_t n = 11)
      : entries_(n), load_(0), maxLoad_(entries_.size() / 2) {
    std::memset(entries_.data(), -1, entries_.size() * sizeof(PartialUse<W>));
  }

  using const_iterator = const PartialUse<W>*;

  PartialUse<W>* end() const { return nullptr; }

  Def<W>& operator[](std::uint32_t useIndex) {
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

  const std::vector<PartialUse<W>>& GetData() const { return entries_; }

  void reserve(size_t n) {
    size_t newSize = GetFirstPrimeGreaterThanOrEqualTo(n * 2);
    std::vector<PartialUse<W>> newEntries(newSize);
    std::memset(newEntries.data(), -1, newSize * sizeof(PartialUse<W>));
    for (size_t oldEntryIndex = 0; oldEntryIndex < entries_.size();
         oldEntryIndex++) {
      PartialUse<W>& oldEntry = entries_[oldEntryIndex];
      if (oldEntry.first == static_cast<std::uint32_t>(-1)) continue;
      PartialUse<W>& newEntry = const_cast<PartialUse<W>&>(
          FindPartialUse(newEntries.data(), newSize, oldEntry.first));
      assert(newEntry.first == (std::uint32_t)-1);
      newEntry = oldEntry;
    }
    entries_.swap(newEntries);
    maxLoad_ = newSize / 2;
  }

 private:
  std::vector<PartialUse<W>> entries_;
  size_t load_;
  size_t maxLoad_;
};

template <typename W, typename UseIterator, typename DefIterator,
          typename PartialUseIterator, typename InsnInTraceIterator>
std::pair<const Def<W>*, std::uint32_t> ResolveUse(
    std::uint32_t useIndex, UseIterator uses, DefIterator defs,
    PartialUseIterator partialUses, size_t partialUseCount,
    InsnInTraceIterator traceBegin, InsnInTraceIterator traceEnd,
    std::uint32_t InsnInTrace::*startDefIndex) {
  std::uint32_t defIndex = uses[useIndex];
  const Def<W>* def;
  const PartialUse<W>& partialUse =
      FindPartialUse(partialUses, partialUseCount, useIndex);
  if (partialUse.first == static_cast<std::uint32_t>(-1))
    def = &*(defs + defIndex);
  else
    def = &partialUse.second;

  InsnInTraceIterator it =
      std::upper_bound(traceBegin, traceEnd, defIndex,
                       [startDefIndex](std::uint32_t defIndex,
                                       const InsnInTrace& trace) -> bool {
                         return defIndex < trace.*startDefIndex;
                       });
  --it;
  std::uint32_t traceIndex = static_cast<std::uint32_t>(it - traceBegin);

  return std::make_pair(def, traceIndex);
}

template <typename W>
class UdState {
 public:
  void Init(size_t expectedUseCount, size_t expectedDefCount,
            size_t expectedPartialUseCount) {
    uses_.reserve(expectedUseCount);
    defs_.reserve(expectedDefCount);
    partialUses_.reserve(expectedPartialUseCount);
    AddDef(0, std::numeric_limits<W>::max());
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
  size_t GetPartialUseCount() const { return partialUses_.GetData().size(); }

  void DumpUses(std::uint32_t startIndex, std::uint32_t endIndex,
                const std::vector<InsnInTrace>& trace,
                std::uint32_t InsnInTrace::*startDefIndex) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startDefIndex);
      std::printf(useIndex == startIndex
                      ? "0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]"
                      : ", 0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIu32 "]",
                  static_cast<std::uint64_t>(use.first->startAddr),
                  static_cast<std::uint64_t>(use.first->endAddr), use.second);
    }
  }

  void DumpDefs(std::uint32_t startIndex, std::uint32_t endIndex) const {
    for (std::uint32_t defIndex = startIndex; defIndex < endIndex; defIndex++)
      std::printf(defIndex == startIndex ? "0x%" PRIx64 "-0x%" PRIx64
                                         : ", 0x%" PRIx64 "-0x%" PRIx64,
                  static_cast<std::uint64_t>(defs_[defIndex].startAddr),
                  static_cast<std::uint64_t>(defs_[defIndex].endAddr));
  }

  void DumpUsesDot(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const std::vector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startDefIndex,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f,
                   "    %" PRIu32 " -> %" PRIu32 " [label=\"%s0x%" PRIx64
                   "-0x%" PRIx64 "\"]\n",
                   traceIndex, use.second, prefix,
                   static_cast<std::uint64_t>(use.first->startAddr),
                   static_cast<std::uint64_t>(use.first->endAddr));
    }
  }

  void DumpUsesHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex,
                    const std::vector<InsnInTrace>& trace,
                    std::uint32_t InsnInTrace::*startDefIndex,
                    const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f,
                   "            <a href=\"#%" PRIu32 "\">%s0x%" PRIx64
                   "-0x%" PRIx64 "</a>\n",
                   use.second, prefix,
                   static_cast<std::uint64_t>(use.first->startAddr),
                   static_cast<std::uint64_t>(use.first->endAddr));
    }
  }

  void DumpDefsHtml(std::FILE* f, std::uint32_t startIndex,
                    std::uint32_t endIndex, const char* prefix) const {
    for (std::uint32_t i = startIndex; i < endIndex; i++)
      std::fprintf(f, "            %s0x%" PRIx64 "-0x%" PRIx64 "\n", prefix,
                   static_cast<std::uint64_t>(defs_[i].startAddr),
                   static_cast<std::uint64_t>(defs_[i].endAddr));
  }

  void DumpUsesCsv(std::FILE* f, std::uint32_t traceIndex,
                   std::uint32_t startIndex, std::uint32_t endIndex,
                   const std::vector<InsnInTrace>& trace,
                   std::uint32_t InsnInTrace::*startDefIndex,
                   const char* prefix) const {
    for (std::uint32_t useIndex = startIndex; useIndex < endIndex; useIndex++) {
      std::pair<const Def<W>*, std::uint32_t> use =
          ResolveUse(useIndex, trace, startDefIndex);
      std::fprintf(f, "%" PRIu32 ",%" PRIu32 ",%s,%" PRIu64 ",%" PRIu64 "\n",
                   traceIndex, use.second, prefix,
                   static_cast<std::uint64_t>(use.first->startAddr),
                   static_cast<std::uint64_t>(use.first->endAddr));
    }
  }

  void DumpUsesBinary(std::FILE* f) const {
    fwrite(uses_.data(), sizeof(std::uint32_t), uses_.size(), f);
  }

  void DumpDefsBinary(std::FILE* f) const {
    fwrite(defs_.data(), sizeof(Def<W>), defs_.size(), f);
  }

  void DumpPartialUsesBinary(std::FILE* f) const {
    fwrite(partialUses_.GetData().data(), sizeof(PartialUse<W>),
           partialUses_.GetData().size(), f);
  }

 private:
  void AddDef(W startAddr, W endAddr) {
    std::uint32_t defIndex = static_cast<std::uint32_t>(defs_.size());
    Def<W>& def = defs_.emplace_back();
    def.startAddr = startAddr;
    def.endAddr = endAddr;
    addressSpace_[endAddr] = EntryValue{startAddr, defIndex};
  }

  std::pair<const Def<W>*, std::uint32_t> ResolveUse(
      std::uint32_t useIndex, const std::vector<InsnInTrace>& trace,
      std::uint32_t InsnInTrace::*startDefIndex) const {
    return ::ResolveUse<W>(useIndex, uses_.begin(), defs_.begin(),
                           partialUses_.GetData().data(),
                           partialUses_.GetData().size(), trace.begin(),
                           trace.end(), startDefIndex);
  }

  std::vector<std::uint32_t> uses_;  // defs_ indices.
  // On average, 4% register and 12% memory uses are partial.
  PartialUses<W> partialUses_;
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
T GetAligned64(T pos) {
  using U = typename Int<sizeof(T)>::U;
  U uPos = (U)pos;
  U aligned = (uPos + static_cast<U>(7)) & ~static_cast<U>(7);
  return (T)aligned;
}

int Align64(FILE* f) {
  long pos = ftell(f);  // // NOLINT(runtime/int)
  if (pos == -1) return -1;
  if (fseek(f, GetAligned64(pos), SEEK_SET) == -1) return -1;
  return 0;
}

template <typename W>
class UdStateMm {
 public:
  const std::uint8_t* Parse(const std::uint8_t* begin, std::uint32_t useCount,
                            std::uint32_t defCount,
                            std::uint32_t partialUseCount) {
    usesBegin_ = reinterpret_cast<const std::uint32_t*>(begin);
    usesEnd_ = usesBegin_ + useCount;
    defsBegin_ = reinterpret_cast<const Def<W>*>(GetAligned64(usesEnd_));
    defsEnd_ = defsBegin_ + defCount;
    partialUsesBegin_ =
        reinterpret_cast<const PartialUse<W>*>(GetAligned64(defsEnd_));
    partialUsesEnd_ = partialUsesBegin_ + partialUseCount;
    return reinterpret_cast<const std::uint8_t*>(partialUsesEnd_);
  }

  template <typename InsnInTraceIterator>
  std::pair<const Def<W>*, std::uint32_t> ResolveUse(
      std::uint32_t useIndex, InsnInTraceIterator traceBegin,
      InsnInTraceIterator traceEnd,
      std::uint32_t InsnInTrace::*startDefIndex) const {
    return ::ResolveUse<W>(useIndex, usesBegin_, defsBegin_, partialUsesBegin_,
                           partialUsesEnd_ - partialUsesBegin_, traceBegin,
                           traceEnd, startDefIndex);
  }

 private:
  const std::uint32_t* usesBegin_;
  const std::uint32_t* usesEnd_;
  const Def<W>* defsBegin_;
  const Def<W>* defsEnd_;
  const PartialUse<W>* partialUsesBegin_;
  const PartialUse<W>* partialUsesEnd_;
};

struct BinaryHeader {
  std::uint8_t magic[2];
  std::uint16_t machineType;
  std::uint32_t textCount;
  std::uint32_t codeCount;
  std::uint32_t traceCount;
  std::uint32_t regUseCount;
  std::uint32_t regDefCount;
  std::uint32_t regPartialUseCount;
  std::uint32_t memUseCount;
  std::uint32_t memDefCount;
  std::uint32_t memPartialUseCount;
};

static_assert(sizeof(BinaryHeader) == 40);

const char kCsvPlaceholder[] = "{}";
constexpr size_t kCsvPlaceholderLength = sizeof(kCsvPlaceholder) - 1;

template <Endianness E, typename W>
class Ud {
 public:
  Ud(const char* dot, const char* html, const char* csv, const char* binary,
     bool verbose)
      : dot_(dot), html_(html), csv_(csv), binary_(binary), verbose_(verbose) {}

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

    std::uint32_t codeIndex = static_cast<std::uint32_t>(code_.size());
    InsnInCode<W>& code = code_.emplace_back();
    code.pc = 0;
    code.textIndex = 0;
    code.textSize = 0;
    disasm_.emplace_back("<unknown>");

    AddTrace(codeIndex);
    // On average, 1.69 register uses and 1.61 register defs per insn.
    regState_.Init(expectedInsnCount * 7 / 4, expectedInsnCount * 5 / 3,
                   expectedInsnCount / 10);
    // On average, 0.4 memory uses and 0.22 memory defs per insn.
    memState_.Init(expectedInsnCount / 2, expectedInsnCount / 4,
                   expectedInsnCount / 20);

    machineType_ = entry.GetMachineType();
    return disasmEngine_.Init(machineType_, E, sizeof(W));
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
    pcs_[entry.GetPc()] = static_cast<std::uint32_t>(code_.size());
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
    if ((ret = DumpBinary()) < 0) return ret;
    return 0;
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

  int DumpBinary() const {
    if (binary_ == nullptr) return 0;
    std::FILE* f = std::fopen(binary_, "wb");
    if (f == nullptr) return -errno;
    BinaryHeader header;
    *reinterpret_cast<std::uint16_t*>(header.magic) =
        ('M' << 8) | ('0' + sizeof(W));
    header.machineType = static_cast<std::uint16_t>(machineType_);
    header.textCount = static_cast<std::uint32_t>(text_.size());
    header.codeCount = static_cast<std::uint32_t>(code_.size());
    header.traceCount = static_cast<std::uint32_t>(trace_.size());
    header.regUseCount = static_cast<std::uint32_t>(regState_.GetUseCount());
    header.regDefCount = static_cast<std::uint32_t>(regState_.GetDefCount());
    header.regPartialUseCount =
        static_cast<std::uint32_t>(regState_.GetPartialUseCount());
    header.memUseCount = static_cast<std::uint32_t>(memState_.GetUseCount());
    header.memDefCount = static_cast<std::uint32_t>(memState_.GetDefCount());
    header.memPartialUseCount =
        static_cast<std::uint32_t>(memState_.GetPartialUseCount());
    fwrite(&header, sizeof(header), 1, f);
    Align64(f);
    fwrite(text_.data(), sizeof(std::uint8_t), text_.size(), f);
    Align64(f);
    fwrite(code_.data(), sizeof(InsnInCode<W>), code_.size(), f);
    Align64(f);
    fwrite(trace_.data(), sizeof(InsnInTrace), trace_.size(), f);
    Align64(f);
    regState_.DumpUsesBinary(f);
    Align64(f);
    regState_.DumpDefsBinary(f);
    Align64(f);
    regState_.DumpPartialUsesBinary(f);
    Align64(f);
    memState_.DumpUsesBinary(f);
    Align64(f);
    memState_.DumpDefsBinary(f);
    Align64(f);
    memState_.DumpPartialUsesBinary(f);
    fclose(f);
    return 0;
  }

  const char* const dot_;
  const char* const html_;
  const char* const csv_;
  const char* const binary_;
  const bool verbose_;
  const char* csvPlaceholder_;
  MachineType machineType_;
  Disasm disasmEngine_;
  std::vector<InsnInCode<W>> code_;
  std::vector<std::uint8_t> text_;
  std::vector<std::string> disasm_;
  std::unordered_map<W, std::uint32_t> pcs_;
  std::vector<InsnInTrace> trace_;
  UdState<W> regState_;
  UdState<W> memState_;
};

class UdMmBase {
 public:
  static UdMmBase* Load(const char* path);

  virtual ~UdMmBase() = default;
  virtual int Parse() = 0;
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
class UdMm : public UdMmBase {
 public:
  UdMm(void* data, size_t length) : data_(data), length_(length) {}
  virtual ~UdMm() { munmap(data_, length_); }

  int Parse() override {
    header_ = static_cast<const BinaryHeader*>(data_);
    int ret;
    if ((ret =
             disasmEngine_.Init(static_cast<MachineType>(header_->machineType),
                                kHostEndianness, sizeof(W))) < 0)
      return ret;
    textBegin_ =
        reinterpret_cast<const std::uint8_t*>(GetAligned64(header_ + 1));
    textEnd_ = textBegin_ + header_->textCount;
    codeBegin_ = reinterpret_cast<const InsnInCode<W>*>(GetAligned64(textEnd_));
    codeEnd_ = codeBegin_ + header_->codeCount;
    traceBegin_ = reinterpret_cast<const InsnInTrace*>(codeEnd_);
    traceEnd_ = traceBegin_ + header_->traceCount;
    const std::uint8_t* regStateEnd = regState_.Parse(
        reinterpret_cast<const std::uint8_t*>(GetAligned64(traceEnd_)),
        header_->regUseCount, header_->regDefCount,
        header_->regPartialUseCount);
    const std::uint8_t* memStateEnd =
        memState_.Parse(GetAligned64(regStateEnd), header_->memUseCount,
                        header_->memDefCount, header_->memPartialUseCount);
    const std::uint8_t* end =
        reinterpret_cast<const std::uint8_t*>(data_) + length_;
    return memStateEnd == end ? 0 : -EINVAL;
  }

  std::vector<std::uint32_t> GetCodesForPc(std::uint64_t pc) const override {
    std::vector<std::uint32_t> codes;
    for (const InsnInCode<W>* code = codeBegin_; code != codeEnd_; code++)
      if (code->pc == pc)
        codes.push_back(static_cast<std::uint32_t>(code - codeBegin_));
    return codes;
  }

  std::uint64_t GetPcForCode(std::uint32_t code) const override {
    return codeBegin_[code].pc;
  }

  std::string GetDisasmForCode(std::uint32_t code) const override {
    const InsnInCode<W>& entry = codeBegin_[code];
    std::unique_ptr<cs_insn, CsFree> insn = disasmEngine_.DoDisasm(
        textBegin_ + entry.textIndex, entry.textSize, entry.pc, 0);
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
    for (const InsnInTrace* trace = traceBegin_; trace != traceEnd_; trace++)
      if (trace->codeIndex == code)
        traces.push_back(static_cast<std::uint32_t>(trace - traceBegin_));
    return traces;
  }

  std::uint32_t GetCodeForTrace(std::uint32_t trace) const override {
    return traceBegin_[trace].codeIndex;
  }

  std::vector<std::uint32_t> GetRegUsesForTrace(
      std::uint32_t trace) const override {
    std::vector<std::uint32_t> regUses;
    for (std::uint32_t regUse = traceBegin_[trace].regUseStartIndex;
         regUse < traceBegin_[trace].regUseEndIndex; regUse++)
      regUses.push_back(regUse);
    return regUses;
  }

  std::vector<std::uint32_t> GetMemUsesForTrace(
      std::uint32_t trace) const override {
    std::vector<std::uint32_t> memUses;
    for (std::uint32_t memUse = traceBegin_[trace].memUseStartIndex;
         memUse < traceBegin_[trace].memUseEndIndex; memUse++)
      memUses.push_back(memUse);
    return memUses;
  }

  std::uint32_t GetTraceForRegUse(std::uint32_t regUse) const override {
    return regState_
        .ResolveUse(regUse, traceBegin_, traceEnd_,
                    &InsnInTrace::regDefStartIndex)
        .second;
  }

  std::uint32_t GetTraceForMemUse(std::uint32_t memUse) const override {
    return memState_
        .ResolveUse(memUse, traceBegin_, traceEnd_,
                    &InsnInTrace::memDefStartIndex)
        .second;
  }

 private:
  void* data_;
  size_t length_;

  const BinaryHeader* header_;
  const std::uint8_t* textBegin_;
  const std::uint8_t* textEnd_;
  const InsnInCode<W>* codeBegin_;
  const InsnInCode<W>* codeEnd_;
  const InsnInTrace* traceBegin_;
  const InsnInTrace* traceEnd_;
  UdStateMm<W> regState_;
  UdStateMm<W> memState_;
  Disasm disasmEngine_;
};

int UdFile(const char* path, size_t start, size_t end, const char* dot,
           const char* html, const char* csv, const char* binary,
           bool verbose) {
  return VisitFile<Ud>(path, start, end, dot, html, csv, binary, verbose);
}

UdMmBase* UdMmBase::Load(const char* path) {
  int err;
  std::uint8_t* data;
  size_t length;
  if ((err = MmapFile(path, 2, &data, &length)) < 0) return nullptr;
  if (data == MAP_FAILED) return nullptr;
  UdMmBase* ud = nullptr;
  switch (data[0] << 8 | data[1]) {
    case 'M' << 8 | '4':
      if (kHostEndianness == Endianness::Big)
        ud = new UdMm<std::uint32_t>(data, length);
      break;
    case 'M' << 8 | '8':
      if (kHostEndianness == Endianness::Big)
        ud = new UdMm<std::uint64_t>(data, length);
      break;
    case '4' << 8 | 'M':
      if (kHostEndianness == Endianness::Little)
        ud = new UdMm<std::uint32_t>(data, length);
      break;
    case '8' << 8 | 'M':
      if (kHostEndianness == Endianness::Little)
        ud = new UdMm<std::uint64_t>(data, length);
      break;
  }
  if (ud == nullptr) {
    munmap(data, length);
    return nullptr;
  }
  if (ud->Parse() < 0) {
    delete ud;
    return nullptr;
  }
  return ud;
}

}  // namespace

BOOST_PYTHON_MODULE(memtrace_ext) {
  namespace bp = boost::python;
  bp::enum_<Endianness>("Endianness")
      .value("BIG_ENDIAN", Endianness::Big)
      .value("LITTLE_ENDIAN", Endianness::Little);
  bp::def("get_endianness_str", GetEndiannessStr);
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
  bp::def("get_tag_str", GetTagStr);
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
  bp::def("get_machine_type_str", GetMachineTypeStr);
  bp::class_<EntryPy>("Entry", bp::no_init)
      .def_readonly("index", &EntryPy::index)
      .def_readonly("tag", &EntryPy::tag);
  bp::class_<LdStEntryPy, bp::bases<EntryPy>>("LdStEntry", bp::no_init)
      .def_readonly("pc", &LdStEntryPy::pc)
      .def_readonly("addr", &LdStEntryPy::addr)
      .def_readonly("value", &LdStEntryPy::value);
  bp::class_<InsnEntryPy, bp::bases<EntryPy>>("InsnEntry", bp::no_init)
      .def_readonly("pc", &InsnEntryPy::pc)
      .def_readonly("value", &InsnEntryPy::value);
  bp::class_<InsnExecEntryPy, bp::bases<EntryPy>>("InsnExecEntry", bp::no_init)
      .def_readonly("pc", &InsnExecEntryPy::pc);
  bp::class_<LdStNxEntryPy, bp::bases<EntryPy>>("LdStNxEntry", bp::no_init)
      .def_readonly("pc", &LdStNxEntryPy::pc)
      .def_readonly("addr", &LdStNxEntryPy::addr)
      .def_readonly("size", &LdStNxEntryPy::size);
  bp::class_<MmapEntryPy, bp::bases<EntryPy>>("MmapEntry", bp::no_init)
      .def_readonly("start", &MmapEntryPy::start)
      .def_readonly("end", &MmapEntryPy::end)
      .def_readonly("flags", &MmapEntryPy::flags)
      .def_readonly("name", &MmapEntryPy::name);
  bp::def("dump_file", DumpFile);
  bp::class_<TraceMmBase, boost::noncopyable>("Trace", bp::no_init)
      .def("load", &TraceMmBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_endianness", &TraceMmBase::GetEndianness)
      .def("get_word_size", &TraceMmBase::GetWordSize)
      .def("get_machine_type", &TraceMmBase::GetMachineType)
      .def("__iter__", bp::objects::identity_function())
      .def("__next__", &TraceMmBase::Next)
      .def("seek_insn", &TraceMmBase::SeekInsn);
  bp::def("ud_file", UdFile);
  bp::class_<std::vector<std::uint8_t>>("std::vector<std::uint8_t>")
      .def(bp::vector_indexing_suite<std::vector<std::uint8_t>>());
  bp::class_<std::vector<std::uint32_t>>("std::vector<std::uint32_t>")
      .def(bp::vector_indexing_suite<std::vector<std::uint32_t>>());
  bp::class_<UdMmBase, boost::noncopyable>("Ud", bp::no_init)
      .def("load", &UdMmBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_codes_for_pc", &UdMmBase::GetCodesForPc)
      .def("get_pc_for_code", &UdMmBase::GetPcForCode)
      .def("get_disasm_for_code", &UdMmBase::GetDisasmForCode)
      .def("get_traces_for_code", &UdMmBase::GetTracesForCode)
      .def("get_code_for_trace", &UdMmBase::GetCodeForTrace)
      .def("get_reg_uses_for_trace", &UdMmBase::GetRegUsesForTrace)
      .def("get_mem_uses_for_trace", &UdMmBase::GetMemUsesForTrace)
      .def("get_trace_for_reg_use", &UdMmBase::GetTraceForRegUse)
      .def("get_trace_for_mem_use", &UdMmBase::GetTraceForMemUse);
  bp::class_<Disasm, boost::noncopyable>("Disasm", bp::no_init)
      .def("__init__", bp::make_constructor(CreateDisasm))
      .def("disasm_str", &Disasm::DisasmStr);
}
