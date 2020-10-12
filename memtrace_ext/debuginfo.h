// Copyright (C) 2020, and GNU GPL'd, by mephi42.
#ifndef DEBUGINFO_H_
#define DEBUGINFO_H_

#include <elfutils/libdwfl.h>

#include <memory>

namespace {  // NOLINT(build/namespaces)

struct DwflDeleter {
  void operator()(Dwfl* dwfl) { dwfl_end(dwfl); }
};

using DwflPtr = std::unique_ptr<Dwfl, DwflDeleter>;

const Dwfl_Callbacks kDwflCallbacks = {
    /* .find_elf = */ dwfl_linux_proc_find_elf,
    /* .find_debuginfo = */ dwfl_standard_find_debuginfo,
    /* .section_address = */ dwfl_offline_section_address,
    /* .debuginfo_path = */ nullptr,
};

DwflPtr DwflBegin() { return DwflPtr(dwfl_begin(&kDwflCallbacks)); }

}  // namespace

#endif  // DEBUGINFO_H_
