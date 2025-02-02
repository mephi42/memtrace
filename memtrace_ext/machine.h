// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#ifndef MACHINE_H_
#define MACHINE_H_

#include <elf.h>

namespace {  // NOLINT(build/namespaces_headers)

enum class MachineType {
  X_EM_386 = EM_386,
  X_EM_X86_64 = EM_X86_64,
  X_EM_PPC = EM_PPC,
  X_EM_PPC64 = EM_PPC64,
  X_EM_ARM = EM_ARM,
  X_EM_AARCH64 = EM_AARCH64,
  X_EM_S390 = EM_S390,
  X_EM_MIPS = EM_MIPS,
  X_EM_NANOMIPS = 249,
};

const char* GetStr(MachineType type) {
  switch (type) {
    case MachineType::X_EM_386:
      return "EM_386";
    case MachineType::X_EM_X86_64:
      return "EM_X86_64";
    case MachineType::X_EM_PPC:
      return "EM_PPC";
    case MachineType::X_EM_PPC64:
      return "EM_PPC64";
    case MachineType::X_EM_ARM:
      return "EM_ARM";
    case MachineType::X_EM_AARCH64:
      return "EM_AARCH64";
    case MachineType::X_EM_S390:
      return "EM_S390";
    case MachineType::X_EM_MIPS:
      return "EM_MIPS";
    case MachineType::X_EM_NANOMIPS:
      return "EM_NANOMIPS";
    default:
      return nullptr;
  }
}

}  // namespace

#endif  // MACHINE_H_
