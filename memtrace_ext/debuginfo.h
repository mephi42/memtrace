// Copyright (C) 2020-2025, and GNU GPL'd, by mephi42.
#ifndef DEBUGINFO_H_
#define DEBUGINFO_H_

#include <elfutils/libdwfl.h>
#include <stdio.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

// clang-format off
#include <boost/optional.hpp>
// clang-format on

namespace {  // NOLINT(build/namespaces_headers)

struct DwflDeleter {
  void operator()(Dwfl* dwfl) { dwfl_end(dwfl); }
};

using DwflPtr = std::unique_ptr<Dwfl, DwflDeleter>;

const Dwfl_Callbacks kDwflCallbacks = {
    /* .find_elf = */ nullptr,
    /* .find_debuginfo = */ dwfl_standard_find_debuginfo,
    /* .section_address = */ nullptr,
    /* .debuginfo_path = */ nullptr,
};

DwflPtr DwflBegin() { return DwflPtr(dwfl_begin(&kDwflCallbacks)); }

class SymbolIndex {
 public:
  explicit SymbolIndex(Dwfl* dwfl) {
    dwfl_getmodules(dwfl, &SymbolIndex::Callback, this, 0);
  }

  boost::optional<GElf_Addr> Find(const char* symbol) const {
    std::map<std::string, GElf_Addr>::const_iterator it = map_.find(symbol);
    if (it == map_.end())
      return boost::none;
    else
      return it->second;
  }

 private:
  /* find_symbol() */
  static int Callback(Dwfl_Module* mod, void** /* userdata */,
                      const char* /* name */, Dwarf_Addr /* start */,
                      void* arg) {
    SymbolIndex* index = reinterpret_cast<SymbolIndex*>(arg);
    for (int i = 1, n = dwfl_module_getsymtab(mod); i < n; ++i) {
      GElf_Sym sym;
      GElf_Addr addr;
      const char* current = dwfl_module_getsym_info(mod, i, &sym, &addr,
                                                    nullptr, nullptr, nullptr);
      if (current == nullptr || *current == 0) continue;
      switch (GELF_ST_TYPE(sym.st_info)) {
        case STT_SECTION:
        case STT_FILE:
        case STT_TLS:
          break;
        default:
          index->map_.insert(std::make_pair(current, addr));
          break;
      }
    }
    return DWARF_CB_OK;
  }

  std::map<std::string, GElf_Addr> map_;
};

struct LinePy {
  LinePy()
      : symbol(nullptr), offset(0), section(nullptr), file(nullptr), line(0) {}

  const char* symbol;
  std::uint64_t offset;
  const char* section;
  const char* file;
  int line;
};

const char* GetSectionName(Dwfl_Module* mod, Dwarf_Addr addr) {
  Dwarf_Addr adjusted = addr;
  Dwarf_Addr bias;
  Elf_Scn* scn = dwfl_module_address_section(mod, &adjusted, &bias);
  if (scn == nullptr) return nullptr;
  GElf_Shdr shdrMem;
  GElf_Shdr* shdr;
  if ((shdr = gelf_getshdr(scn, &shdrMem)) == nullptr) return nullptr;
  Elf* elf = dwfl_module_getelf(mod, &bias);
  size_t shstrndx;
  if (elf_getshdrstrndx(elf, &shstrndx) < 0) return nullptr;
  return elf_strptr(elf, shstrndx, shdr->sh_name);
}

/* print_addrsym() */
LinePy FindAddr(Dwfl* dwfl, std::uint64_t addr) {
  LinePy linePy;
  Dwfl_Module* mod = dwfl_addrmodule(dwfl, addr);
  if (mod == nullptr) return linePy;
  GElf_Off offset;
  GElf_Sym sym;
  const char* symbol =
      dwfl_module_addrinfo(mod, addr, &offset, &sym, nullptr, nullptr, nullptr);
  if (symbol != nullptr) {
    linePy.symbol = strdup(symbol);
    linePy.offset = offset;
  }

  const char* sectionName = GetSectionName(mod, addr);
  if (sectionName != nullptr) linePy.section = strdup(sectionName);

  Dwfl_Line* line = dwfl_module_getsrc(mod, addr);
  if (line == nullptr) return linePy;
  int linep;
  const char* file =
      dwfl_lineinfo(line, nullptr, &linep, nullptr, nullptr, nullptr);
  if (file == nullptr) return linePy;
  linePy.file = strdup(file);
  linePy.line = linep;
  return linePy;
}

void PrintNamePlusOffset(FILE* f, const char* name, Dwarf_Addr offset) {
  if (offset == 0)
    fprintf(f, "%s", name);
  else
    fprintf(f, "%s+0x%" PRIx64, name, static_cast<std::uint64_t>(offset));
}

void PrintAddr(FILE* f, Dwfl_Module* mod, Dwarf_Addr addr) {
  if (mod == nullptr) {
    fprintf(f, "0x%" PRIx64, static_cast<std::uint64_t>(addr));
    return;
  }
  GElf_Off offset;
  GElf_Sym sym;
  const char* symbolName =
      dwfl_module_addrinfo(mod, addr, &offset, &sym, nullptr, nullptr, nullptr);
  if (symbolName == nullptr) {
    Dwarf_Addr start;
    const char* moduleName = dwfl_module_info(
        mod, nullptr, &start, nullptr, nullptr, nullptr, nullptr, nullptr);
    PrintNamePlusOffset(f, moduleName, addr - start);
  } else {
    PrintNamePlusOffset(f, symbolName, offset);
  }
}

}  // namespace

#endif  // DEBUGINFO_H_
