// Copyright (C) 2020, and GNU GPL'd, by mephi42.
#ifndef DEBUGINFO_H_
#define DEBUGINFO_H_

#include <elfutils/libdwfl.h>
#include <string.h>

#include <boost/optional.hpp>
#include <cstdint>
#include <memory>

namespace {  // NOLINT(build/namespaces)

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

struct SymbolFinder {
  /* find_symbol() */
  static int Callback(Dwfl_Module* mod, void** /* userdata */,
                      const char* /* name */, Dwarf_Addr /* start */,
                      void* arg) {
    SymbolFinder* finder = reinterpret_cast<SymbolFinder*>(arg);
    for (int i = 1, n = dwfl_module_getsymtab(mod); i < n; ++i) {
      GElf_Sym sym;
      const char* current = dwfl_module_getsym_info(mod, i, &sym, &finder->addr,
                                                    nullptr, nullptr, nullptr);
      if (current == nullptr || *current == 0) continue;
      switch (GELF_ST_TYPE(sym.st_info)) {
        case STT_SECTION:
        case STT_FILE:
        case STT_TLS:
          break;
        default:
          if (strcmp(current, finder->name) == 0) {
            finder->name = nullptr;
            return DWARF_CB_ABORT;
          }
      }
    }
    return DWARF_CB_OK;
  }

  const char* name;
  GElf_Addr addr;
};

boost::optional<std::uint64_t> FindSymbol(Dwfl* dwfl, const char* symbol) {
  SymbolFinder finder = {symbol, 0};
  dwfl_getmodules(dwfl, &SymbolFinder::Callback, &finder, 0);
  if (finder.name == nullptr)
    return finder.addr;
  else
    return boost::none;
}

struct LinePy {
  LinePy()
      : symbol(nullptr), offset(0), section(nullptr), file(nullptr), line(0) {}

  const char* symbol;
  std::uint64_t offset;
  const char* section;
  const char* file;
  int line;
};

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

  Dwarf_Addr adjusted = addr;
  Dwarf_Addr bias;
  Elf_Scn* scn = dwfl_module_address_section(mod, &adjusted, &bias);
  if (scn != nullptr) {
    GElf_Shdr shdrMem;
    GElf_Shdr* shdr;
    if ((shdr = gelf_getshdr(scn, &shdrMem)) != nullptr) {
      Elf* elf = dwfl_module_getelf(mod, &bias);
      size_t shstrndx;
      if (elf_getshdrstrndx(elf, &shstrndx) >= 0)
        linePy.section = strdup(elf_strptr(elf, shstrndx, shdr->sh_name));
    }
  }

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

}  // namespace

#endif  // DEBUGINFO_H_
