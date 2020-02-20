// Copyright (C) 2019-2020, and GNU GPL'd, by mephi42.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>

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
  size_t GetLength() const {
    return (size_t)RawInt<std::uint16_t, E, W>(data_ + 2).GetValue();
  }

  size_t GetAlignedLength() const {
    return (GetLength() + (sizeof(W) - 1)) & ~(sizeof(W) - 1);
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
  size_t GetSize() const { return GetTlv().GetLength() - sizeof(W) * 3; }

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
  size_t GetSize() const { return GetTlv().GetLength() - sizeof(W) * 2; }

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

void HexDump(const uint8_t* buf, size_t n) {
  for (size_t i = 0; i < n; i++) std::printf("%02x", buf[i]);
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

template <Endianness E, typename W>
class Dumper {
 public:
  Dumper() : insnCount_(0), capstone_(0) {}
  ~Dumper() {
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
    HexDump(entry.GetValue(), entry.GetSize());
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(capstone_, entry.GetValue(), entry.GetSize(),
                             entry.GetPc(), 0, &insn);
    if (insn)
      std::printf(" %s %s\n", insn->mnemonic, insn->op_str);
    else
      std::printf(" <unknown>\n");
    cs_free(insn, count);
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

  size_t GetInsnCount() const { return insnCount_; }

 private:
  size_t insnCount_;
  csh capstone_;
};

template <Endianness E, typename W>
int Rest(std::istream* is, Buffer* buf, size_t start, size_t end) {
  HeaderEntry<E, std::uint64_t> entry(buf->GetData());
  std::printf("Endian            : %s\n", GetEndiannessStr(E));
  std::printf("Word              : %s\n", sizeof(W) == 4 ? "I" : "Q");
  std::printf("Word size         : %zu\n", sizeof(W));
  std::printf("Machine           : %s\n",
              GetMachineTypeStr(entry.GetMachineType()));
  buf->Advance(entry.GetTlv().GetAlignedLength());
  Dumper<E, W> dumper;
  if (dumper.Init(entry.GetMachineType()) < 0) {
    std::cerr << "dumper.Init() failed" << std::endl;
    return EXIT_FAILURE;
  }
  size_t i = 0;
  while (buf->GetSize() > 0) {
    if (Parse<E, W>(&dumper, buf, &i, start, end) < 0) {
      std::cerr << "Parse(buf) failed" << std::endl;
      return EXIT_FAILURE;
    }
    if (buf->Update(is) < 0) {
      std::cerr << "buf.Update() failed" << std::endl;
      return EXIT_FAILURE;
    }
  }
  std::printf("Insns             : %zu\n", dumper.GetInsnCount());
  return EXIT_SUCCESS;
}

int DumpFile(const char* path, size_t start, size_t end) {
  std::ifstream is(path);
  if (!is) {
    std::cerr << "Could not open " << path << std::endl;
    return EXIT_FAILURE;
  }
  Buffer buf;
  if (buf.Update(&is) < 0 || buf.GetSize() < 2) {
    std::cerr << "buf.Update() failed" << std::endl;
    return EXIT_FAILURE;
  }
  if (buf.GetData()[0] == 'M' && buf.GetData()[1] == '4') {
    return Rest<Endianness::Big, std::uint32_t>(&is, &buf, start, end);
  } else if (buf.GetData()[0] == 'M' && buf.GetData()[1] == '8') {
    return Rest<Endianness::Big, std::uint64_t>(&is, &buf, start, end);
  } else if (buf.GetData()[0] == '4' && buf.GetData()[1] == 'M') {
    return Rest<Endianness::Little, std::uint32_t>(&is, &buf, start, end);
  } else if (buf.GetData()[0] == '8' && buf.GetData()[1] == 'M') {
    return Rest<Endianness::Little, std::uint64_t>(&is, &buf, start, end);
  } else {
    std::cerr << "Unsupported magic" << std::endl;
    return EXIT_FAILURE;
  }
}

}  // namespace

BOOST_PYTHON_MODULE(memtrace_ext) { boost::python::def("dump_file", DumpFile); }
