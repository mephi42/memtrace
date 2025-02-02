// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef DISASM_H_
#define DISASM_H_

#include <memory>
#include <string>
#include <vector>

// clang-format off
#include <capstone/capstone.h>  // NOLINT(build/include_order)
// clang-format on

#include "./endian.h"
#include "./machine.h"

namespace {  // NOLINT(build/namespaces_headers)

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
      case MachineType::X_EM_386:
        if (endianness != Endianness::Little || wordSize != 4) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_32;
        break;
      case MachineType::X_EM_X86_64:
        if (endianness != Endianness::Little || wordSize != 8) return -EINVAL;
        arch = CS_ARCH_X86;
        mode = CS_MODE_64;
        break;
        // EM_PPC is not supported.
      case MachineType::X_EM_PPC64:
        if (wordSize != 8) return -EINVAL;
        arch = CS_ARCH_PPC;
        if (endianness == Endianness::Little)
          mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN);
        else
          mode = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::X_EM_ARM:
        if (wordSize != 4) return -EINVAL;
        arch = CS_ARCH_ARM;
        if (endianness == Endianness::Little)
          mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
        else
          mode = static_cast<cs_mode>(CS_MODE_ARM | CS_MODE_BIG_ENDIAN);
        break;
      case MachineType::X_EM_AARCH64:
        if (wordSize != 8) return -EINVAL;
        arch = CS_ARCH_ARM64;
        if (endianness == Endianness::Little)
          mode = CS_MODE_LITTLE_ENDIAN;
        else
          mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::X_EM_S390:
        if (endianness != Endianness::Big) return -EINVAL;
        arch = CS_ARCH_SYSZ;
        mode = CS_MODE_BIG_ENDIAN;
        break;
      case MachineType::X_EM_MIPS:
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
        // X_EM_NANOMIPS is not supported.
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

}  // namespace

#endif  // DISASM_H_
