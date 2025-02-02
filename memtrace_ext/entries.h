// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef ENTRIES_H_
#define ENTRIES_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "./endian.h"
#include "./identifier.h"
#include "./machine.h"

namespace {  // NOLINT(build/namespaces_headers)

enum class Tag {
  MT_HEADER32 = 0x4d34,
  MT_HEADER64 = 0x4d38,
  MT_LOAD = 0x4d41,
  MT_STORE = 0x4d42,
  MT_REG = 0x4d43,
  MT_INSN = 0x4d44,
  MT_GET_REG = 0x4d45,
  MT_PUT_REG = 0x4d46,
  MT_INSN_EXEC = 0x4d47,
  MT_GET_REG_NX = 0x4d48,
  MT_PUT_REG_NX = 0x4d49,
  MT_MMAP = 0x4d50,
  MT_REGMETA = 0x4d51,

  MT_LAST,
  MT_FIRST = MT_LOAD,
};

const char* GetStr(Tag tag) {
  switch (tag) {
    case Tag::MT_HEADER32:
      return "MT_HEADER32";
    case Tag::MT_HEADER64:
      return "MT_HEADER64";
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
    case Tag::MT_REGMETA:
      return "MT_REGMETA";
    default:
      return nullptr;
  }
}

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
  std::uint32_t GetLength() const {
    return RawInt<E, std::uint16_t>(this->GetData() + 2).GetValue();
  }
  std::uint32_t GetAlignedLength() const {
    return (GetLength() + (static_cast<std::uint32_t>(sizeof(W)) - 1)) &
           ~(static_cast<std::uint32_t>(sizeof(W)) - 1);
  }
};

using TraceId = std::array<std::uint8_t, 16>;

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
  const TraceId& GetTraceId() const {
    return *reinterpret_cast<const TraceId*>(this->GetData() + kTraceIdOffset);
  }

 private:
  static constexpr size_t kMachineTypeOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kRegsSizeOffset =
      kMachineTypeOffset + sizeof(std::uint16_t);
  static constexpr size_t kTraceIdOffset =
      kRegsSizeOffset + sizeof(std::uint16_t);
};

DEFINE_IDENTIFIER(InsnSeq, std::uint32_t);
#define PRIuInsnSeq PRIu32
#define PRIxInsnSeq PRIx32

template <Endianness E, typename W, typename B = Overlay>
class LdStEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  InsnSeq GetInsnSeq() const {
    return InsnSeq{
        RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset).GetValue()};
  }
  W GetAddr() const {
    return RawInt<E, W>(this->GetData() + kAddrOffset).GetValue();
  }
  const std::uint8_t* GetValue() const {
    return this->GetData() + kValueOffset;
  }
  std::uint32_t GetSize() const {
    return GetTlv().GetLength() - static_cast<std::uint32_t>(kValueOffset);
  }
  std::vector<std::uint8_t> CopyValue() const {
    return std::vector<std::uint8_t>(GetValue(), GetValue() + GetSize());
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kAddrOffset = kInsnSeqOffset + sizeof(std::uint32_t);
  static constexpr size_t kValueOffset = kAddrOffset + sizeof(W);
};

enum class InsnFlags : std::uint8_t {
  MT_INSN_INDIRECT_JUMP = (1 << 0),
};

const char* GetStr(InsnFlags flags) {
  switch (flags) {
    case InsnFlags::MT_INSN_INDIRECT_JUMP:
      return "MT_INSN_INDIRECT_JUMP";
    default:
      return nullptr;
  }
}

template <Endianness E, typename W, typename B = Overlay>
class InsnEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  InsnSeq GetInsnSeq() const {
    return InsnSeq{
        RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset).GetValue()};
  }
  W GetPc() const {
    return RawInt<E, W>(this->GetData() + kPcOffset).GetValue();
  }
  std::uint8_t GetFlags() const {
    return RawInt<E, std::uint8_t>(this->GetData() + kFlagsOffset).GetValue();
  }
  const std::uint8_t* GetValue() const {
    return this->GetData() + kValueOffset;
  }
  std::uint32_t GetSize() const {
    return GetTlv().GetLength() - static_cast<std::uint32_t>(kValueOffset);
  }
  std::vector<std::uint8_t> CopyValue() const {
    return std::vector<std::uint8_t>(GetValue(), GetValue() + GetSize());
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kPcOffset = kInsnSeqOffset + sizeof(std::uint32_t);
  static constexpr size_t kFlagsOffset = kPcOffset + sizeof(W);
  static constexpr size_t kValueOffset = kFlagsOffset + sizeof(std::uint8_t);
};

template <Endianness E, typename W, typename B = Overlay>
class InsnExecEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  InsnSeq GetInsnSeq() const {
    return InsnSeq{
        RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset).GetValue()};
  }

 private:
  static constexpr size_t kInsnSeqOffset = Tlv<E, W>::kFixedLength;
};

template <Endianness E, typename W, typename B = Overlay>
class LdStNxEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  InsnSeq GetInsnSeq() const {
    return InsnSeq{
        RawInt<E, std::uint32_t>(this->GetData() + kInsnSeqOffset).GetValue()};
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
  const char* GetValue() const {
    return reinterpret_cast<const char*>(this->GetData() + kValueOffset);
  }
  std::uint32_t GetSize() const {
    return GetTlv().GetLength() - static_cast<std::uint32_t>(kValueOffset);
  }
  std::string CopyValue() const { return GetValue(); }

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

template <Endianness E, typename W, typename B = Overlay>
class RegMetaEntry : public B {
 public:
  using B::B;

  Tlv<E, W> GetTlv() const { return Tlv<E, W>(this->GetData()); }
  std::uint16_t GetOffset() const {
    return RawInt<E, std::uint16_t>(this->GetData() + kOffsetOffset).GetValue();
  }
  std::uint16_t GetSize() const {
    return RawInt<E, std::uint16_t>(this->GetData() + kSizeOffset).GetValue();
  }
  const char* GetName() const {
    return reinterpret_cast<const char*>(this->GetData() + kNameOffset);
  }
  std::string CopyName() const { return GetName(); }

 private:
  static constexpr size_t kOffsetOffset = Tlv<E, W>::kFixedLength;
  static constexpr size_t kSizeOffset = kOffsetOffset + sizeof(std::uint16_t);
  static constexpr size_t kNameOffset = kSizeOffset + sizeof(std::uint16_t);
};

}  // namespace

#endif  // ENTRIES_H_
