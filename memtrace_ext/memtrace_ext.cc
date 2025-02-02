// Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cinttypes>
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
#include <set>
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
// clang-format on

#include "./align.h"
#include "./debuginfo.h"
#include "./disasm.h"
#include "./endian.h"
#include "./entries.h"
#include "./identifier.h"
#include "./machine.h"
#include "./mmvector.h"

namespace {

constexpr size_t kHostWordSize = sizeof(void*);

void HexDump(std::FILE* f, const void* buf, size_t n) {
  for (size_t i = 0; i < n; i++)
    std::fprintf(f, "%02x", static_cast<const std::uint8_t*>(buf)[i]);
}

void ReprDump(std::FILE* f, const std::uint8_t* buf, size_t n) {
  std::fprintf(f, "b'");
  for (size_t i = 0; i < n; i++) std::fprintf(f, "\\x%02x", buf[i]);
  std::fprintf(f, "'");
}

template <Endianness E>
void ValueDump(FILE* f, const std::uint8_t* buf, size_t n) {
  switch (n) {
    case 1:
      std::fprintf(f, "0x%" PRIx8, RawInt<E, std::uint8_t>(buf).GetValue());
      break;
    case 2:
      std::fprintf(f, "0x%" PRIx16, RawInt<E, std::uint16_t>(buf).GetValue());
      break;
    case 4:
      std::fprintf(f, "0x%" PRIx32, RawInt<E, std::uint32_t>(buf).GetValue());
      break;
    case 8:
      std::fprintf(f, "0x%" PRIx64, RawInt<E, std::uint64_t>(buf).GetValue());
      break;
    default:
      ReprDump(f, buf, n);
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

template <typename Header>
int ReadHeader(const char* path, Header* header) {
  FILE* f = fopen(path, "r");
  if (f == nullptr) return -errno;
  size_t n_read = fread(header, sizeof(*header), 1, f);
  fclose(f);
  return n_read == 1 ? 0 : -EIO;
}

template <typename Header>
int WriteHeader(const char* path, const Header& header) {
  std::FILE* f = std::fopen(path, "wb");
  if (f == nullptr) return -errno;
  size_t n_written = fwrite(&header, sizeof(header), 1, f);
  fclose(f);
  return n_written == 1 ? 0 : -EIO;
}

template <Endianness E, typename W>
class Trace;

template <Endianness E, typename W>
void DisasmInsnEntry(FILE* f, const Disasm& disasmEngine,
                     InsnEntry<E, W> entry) {
  HexDump(f, entry.GetValue(), entry.GetSize());
  std::unique_ptr<cs_insn, CsFree> insn = disasmEngine.DoDisasm(
      entry.GetValue(), entry.GetSize(), entry.GetPc(), 0);
  if (insn)
    std::fprintf(f, " %s %s\n", insn->mnemonic, insn->op_str);
  else
    std::fprintf(f, " <unknown>\n");
}

template <Endianness E, typename W>
class Dumper {
 public:
  explicit Dumper(std::FILE* f, Trace<E, W>* trace, bool header, bool summary)
      : f_(f),
        trace_(trace),
        header_(header),
        summary_(summary),
        insnCount_(0) {}

  int Init(HeaderEntry<E, W> entry, size_t /* expectedInsnCount */) {
    if (header_) {
      std::fprintf(f_, "Endian            : %s\n", GetEndiannessStrPy(E));
      std::fprintf(f_, "Word              : %s\n", sizeof(W) == 4 ? "I" : "Q");
      std::fprintf(f_, "Word size         : %zu\n", sizeof(W));
      std::fprintf(f_, "Machine           : %s\n",
                   GetStr(entry.GetMachineType()));
      std::fprintf(f_, "Regs size         : %d\n", entry.GetRegsSize());
      std::fprintf(f_, "Trace ID          : ");
      HexDump(f_, &entry.GetTraceId(), sizeof(TraceId));
      std::fprintf(f_, "\n");
    }
    return disasmEngine_.Init(entry.GetMachineType(), E, sizeof(W));
  }

  int operator()(size_t i, LdStEntry<E, W> entry) {
    const char* regName;
    Tag tag = entry.GetTlv().GetTag();
    if (tag == Tag::MT_REG || tag == Tag::MT_GET_REG || tag == Tag::MT_PUT_REG)
      regName = trace_->GetRegName(static_cast<std::uint16_t>(entry.GetAddr()),
                                   static_cast<std::uint16_t>(entry.GetSize()));
    else
      regName = nullptr;
    if (regName == nullptr)
      std::fprintf(
          f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s uint%zu_t [0x%" PRIx64 "] ", i,
          entry.GetInsnSeq().value, GetStr(tag),
          static_cast<size_t>(entry.GetSize() * 8),
          static_cast<std::uint64_t>(entry.GetAddr()));
    else
      std::fprintf(f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s %s ", i,
                   entry.GetInsnSeq().value, GetStr(tag), regName);
    ValueDump<E>(f_, entry.GetValue(), entry.GetSize());
    std::fprintf(f_, "\n");
    return 0;
  }

  int operator()(size_t i, InsnEntry<E, W> entry) {
    std::fprintf(f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s 0x%016" PRIx64 " ", i,
                 entry.GetInsnSeq().value, GetStr(entry.GetTlv().GetTag()),
                 static_cast<std::uint64_t>(entry.GetPc()));
    if (entry.GetFlags() & static_cast<std::underlying_type_t<InsnFlags>>(
                               InsnFlags::MT_INSN_INDIRECT_JUMP))
      std::fprintf(f_, "%s ", GetStr(InsnFlags::MT_INSN_INDIRECT_JUMP));
    DisasmInsnEntry(f_, disasmEngine_, entry);
    return 0;
  }

  int operator()(size_t i, InsnExecEntry<E, W> entry) {
    std::fprintf(f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s\n", i,
                 entry.GetInsnSeq().value, GetStr(entry.GetTlv().GetTag()));
    insnCount_++;
    return 0;
  }

  int operator()(size_t i, LdStNxEntry<E, W> entry) {
    const char* regName =
        trace_->GetRegName(static_cast<std::uint16_t>(entry.GetAddr()),
                           static_cast<std::uint16_t>(entry.GetSize()));
    if (regName == nullptr)
      std::fprintf(
          f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s uint%zu_t [0x%" PRIx64 "]\n", i,
          entry.GetInsnSeq().value, GetStr(entry.GetTlv().GetTag()),
          static_cast<size_t>(entry.GetSize() * 8),
          static_cast<std::uint64_t>(entry.GetAddr()));
    else
      std::fprintf(f_, "[%10zu] 0x%08" PRIxInsnSeq ": %s %s\n", i,
                   entry.GetInsnSeq().value, GetStr(entry.GetTlv().GetTag()),
                   regName);
    return 0;
  }

  int operator()(size_t i, MmapEntry<E, W> entry) {
    std::fprintf(f_, "[%10zu] %s %016" PRIx64 "-%016" PRIx64 " %c%c%c %s\n", i,
                 GetStr(entry.GetTlv().GetTag()),
                 static_cast<std::uint64_t>(entry.GetStart()),
                 static_cast<std::uint64_t>(entry.GetEnd() + 1),
                 entry.GetFlags() & 1 ? 'r' : '-',
                 entry.GetFlags() & 2 ? 'w' : '-',
                 entry.GetFlags() & 4 ? 'x' : '-', entry.GetValue());
    return 0;
  }

  int operator()(size_t i, RegMetaEntry<E, W> entry) {
    std::fprintf(f_, "[%10zu] %s uint%zu_t %s [0x%" PRIx16 "]\n", i,
                 GetStr(entry.GetTlv().GetTag()),
                 static_cast<size_t>(entry.GetSize() * 8), entry.GetName(),
                 entry.GetOffset());
    return 0;
  }

  int Complete() {
    if (summary_) std::fprintf(f_, "Insns             : %zu\n", insnCount_);
    return 0;
  }

 private:
  FILE* f_;
  Trace<E, W>* trace_;
  const bool header_;
  const bool summary_;
  size_t insnCount_;
  Disasm disasmEngine_;
};

template <Endianness E, typename W>
class SourceDumper {
 public:
  SourceDumper(std::FILE* f, Trace<E, W>* trace)
      : f_(f), trace_(trace), prevFile_(nullptr), prevLinep_(-1) {}

  int Init(HeaderEntry<E, W> entry, size_t /* expectedInsnCount */) {
    return disasmEngine_.Init(entry.GetMachineType(), E, sizeof(W));
  }

  int operator()(size_t /* i */, InsnEntry<E, W> entry) {
    if (!insns_.empty() && entry.GetInsnSeq().value !=
                               insns_[0].GetInsnSeq().value + insns_.size())
      return -EINVAL;
    insns_.push_back(entry);
    return 0;
  }

  int operator()(size_t /* index */, InsnExecEntry<E, W> entry) {
    if (insns_.empty()) return -EINVAL;
    size_t insnIndex = entry.GetInsnSeq().value - insns_[0].GetInsnSeq().value;
    if (insnIndex >= insns_.size()) return -EINVAL;
    int err;
    if ((err = trace_->UpdateDwfl()) < 0) return err;
    InsnEntry<E, W> insn = insns_[insnIndex];
    Dwfl_Module* mod = dwfl_addrmodule(trace_->dwfl_.get(), insn.GetPc());
    Dwfl_Line* line =
        mod == nullptr ? nullptr : dwfl_module_getsrc(mod, insn.GetPc());
    if (line == nullptr) {
      PrintAddr(f_, mod, insn.GetPc());
      std::fprintf(f_, ": ");
      DisasmInsnEntry(f_, disasmEngine_, insn);
      prevFile_ = nullptr;
      prevLinep_ = -1;
      return 0;
    }
    int linep;
    const char* file =
        dwfl_lineinfo(line, nullptr, &linep, nullptr, nullptr, nullptr);
    if (linep != prevLinep_ || prevFile_ == nullptr ||
        (prevFile_ != file && strcmp(prevFile_, file) != 0))
      std::fprintf(f_, "%s:%d\n", file, linep);
    prevFile_ = file;
    prevLinep_ = linep;
    return 0;
  }

  template <typename Entry>
  int operator()(size_t /* index */, Entry /* entry */) {
    return 0;
  }

  int Complete() { return 0; }

 private:
  FILE* f_;
  Trace<E, W>* trace_;
  static_assert(sizeof(InsnEntry<E, W>) == sizeof(void*));
  std::vector<InsnEntry<E, W>> insns_;
  const char* prevFile_;
  int prevLinep_;
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
  TraceEntry2Py() : py(nullptr) {}

  template <typename Entry>
  int operator()(size_t index, Entry entry) {
    py = CreateEntryPy(index, entry);
    return 0;
  }

  EntryPy* py;
};

struct NoOp {
  template <typename Entry>
  int operator()(size_t /*index*/, Entry /*entry*/) {
    return 0;
  }
};

DEFINE_IDENTIFIER(TraceIndex, std::uint32_t);
#define PRIuTraceIndex PRIu32
#define PRIxTraceIndex PRIx32
constexpr TraceIndex kFirstTraceIndex{1};

struct Seeker {
  Seeker()
      : traceIndex{kFirstTraceIndex.value - 1},
        prevInsnSeq{std::numeric_limits<InsnSeq::value_type>::max()} {}

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

  template <Endianness E, typename W>
  int operator()(size_t /* index */, RegMetaEntry<E, W> /* entry */) {
    return 0;
  }

  int HandleInsnSeq(InsnSeq insnSeq) {
    if (insnSeq != prevInsnSeq) {
      traceIndex.value++;
      prevInsnSeq = insnSeq;
    }
    return 0;
  }

  TraceIndex traceIndex;
  InsnSeq prevInsnSeq;
};

struct Indexer {
  Indexer() : isMmap(false) {}

  template <Endianness E, typename W>
  int operator()(size_t index, MmapEntry<E, W> entry) {
    isMmap = true;
    return seeker(index, entry);
  }

  template <typename Entry>
  int operator()(size_t index, Entry entry) {
    isMmap = false;
    return seeker(index, entry);
  }

  bool isMmap;
  Seeker seeker;
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

struct InsnIndexEntry {
  size_t fileOffset;
  size_t entryIndex;
};

struct MmapIndexEntry {
  size_t fileOffset;
};

struct TraceFilter {
  TraceFilter()
      : firstEntryIndex(std::numeric_limits<size_t>::min()),
        lastEntryIndex(std::numeric_limits<size_t>::max()),
        tagMask(static_cast<std::uint32_t>(-1)) {}

  bool isEntryIndexOk(size_t entryIndex) const {
    return entryIndex >= firstEntryIndex && entryIndex <= lastEntryIndex;
  }

  bool isTagOk(Tag tag) const {
    return tagMask & (1 << (static_cast<std::uint16_t>(tag) -
                            static_cast<std::uint16_t>(Tag::MT_FIRST)));
  }

  std::vector<InsnSeq> GetInsnSeqs() const {
    return std::vector<InsnSeq>(insnSeqs.begin(), insnSeqs.end());
  }

  void SetInsnSeqs(const std::vector<InsnSeq>& insnSeqs) {
    this->insnSeqs = std::set<InsnSeq>(insnSeqs.begin(), insnSeqs.end());
  }

  bool isMissingInsnSeqOk() const { return insnSeqs.empty(); }

  bool isInsnSeqOk(InsnSeq insnSeq) const {
    return insnSeqs.empty() || insnSeqs.find(insnSeq) != insnSeqs.end();
  }

  size_t firstEntryIndex;
  size_t lastEntryIndex;
  std::uint32_t tagMask;
  std::set<InsnSeq> insnSeqs;
};

struct TraceFilterNoOp {
  bool isEntryIndexOk(size_t /* entryIndex */) const { return true; }
  bool isTagOk(Tag /* tag */) const { return true; }
  bool isMissingInsnSeqOk() const { return true; }
  bool isInsnSeqOk(InsnSeq /* insnSeq */) const { return true; }
};

enum class DumpKind {
  Raw,
  Source,
};

const char* GetStr(DumpKind kind) {
  switch (kind) {
    case DumpKind::Raw:
      return "Raw";
    case DumpKind::Source:
      return "Source";
    default:
      return nullptr;
  }
}

namespace bp = boost::python;

class TraceBase {
 public:
  static TraceBase* Load(const char* path);
  template <typename V>
  static void Downcast(std::shared_ptr<TraceBase> trace, const V& v);

  virtual ~TraceBase() = default;
  virtual Endianness GetEndianness() = 0;
  virtual size_t GetWordSize() = 0;
  virtual MachineType GetMachineType() = 0;
  virtual std::uint16_t GetRegsSize() = 0;
  virtual TraceId GetTraceId() = 0;
  virtual std::vector<std::uint8_t> GetTraceIdPy() = 0;
  virtual bp::object Next() = 0;
  virtual int SeekStart() = 0;
  virtual int SeekInsn(TraceIndex traceIndex) = 0;
  virtual int SeekEnd() = 0;
  virtual Stats GatherStats() = 0;
  virtual bool HasInsnIndex() = 0;
  virtual int BuildInsnIndex(const char* path, size_t stepShift) = 0;
  virtual int LoadInsnIndex(const char* path) = 0;
  virtual int Dump(const char* path, DumpKind kind, bool header,
                   bool summary) = 0;
  virtual void SetFilter(std::shared_ptr<TraceFilter> filter) = 0;
  virtual const char* GetRegName(std::uint16_t offset, std::uint16_t size) = 0;
  virtual LinePy Symbolize(std::uint64_t addr) = 0;
  virtual bp::object Resolve(const char* symbol) = 0;
};

template <typename W>
struct Range {
  Range() {}
  Range(W startAddr, W endAddr) : startAddr(startAddr), endAddr(endAddr) {}

  bool operator==(const Range& rhs) const {
    return startAddr == rhs.startAddr && endAddr == rhs.endAddr;
  }

  W startAddr;
  W endAddr;
};

DEFINE_IDENTIFIER(RegDefIndex, std::uint32_t);
DEFINE_IDENTIFIER(MemDefIndex, std::uint32_t);

template <typename W>
struct DefSeeker {
  DefSeeker()
      : relativeDefIndex(std::numeric_limits<std::uint32_t>::max()),
        range({0, 0}) {}

  void HandleDef(W start, W end) {
    relativeDefIndex++;
    range = {start, end};
  }

  std::uint32_t relativeDefIndex;
  Range<W> range;

  template <typename Entry>
  int operator()(size_t /* i */, Entry /* entry */) {
    return 0;
  }
};

template <typename W>
struct RegDefSeeker : public DefSeeker<W> {
  template <Endianness E>
  int operator()(size_t /* i */, LdStEntry<E, W> entry) {
    if (entry.GetTlv().GetTag() == Tag::MT_PUT_REG)
      this->HandleDef(entry.GetAddr(), entry.GetAddr() + entry.GetSize());
    return 0;
  }

  template <Endianness E>
  int operator()(size_t /* i */, LdStNxEntry<E, W> entry) {
    if (entry.GetTlv().GetTag() == Tag::MT_PUT_REG_NX)
      this->HandleDef(entry.GetAddr(), entry.GetAddr() + entry.GetSize());
    return 0;
  }

  using DefSeeker<W>::operator();
};

template <typename W>
struct MemDefSeeker : public DefSeeker<W> {
  template <Endianness E>
  int operator()(size_t /* i */, LdStEntry<E, W> entry) {
    if (entry.GetTlv().GetTag() == Tag::MT_STORE)
      this->HandleDef(entry.GetAddr(), entry.GetAddr() + entry.GetSize());
    return 0;
  }

  using DefSeeker<W>::operator();
};

struct InsnIndexHeader {
  TraceId traceId;
  std::uint8_t stepShift;
};

using RegMeta = std::map<std::pair<std::uint16_t, std::uint16_t>, const char*>;

struct HeaderVisitor {
  explicit HeaderVisitor(RegMeta* regMeta) : regMeta(regMeta), proceed(true) {}

  template <Endianness E, typename W>
  int operator()(size_t /* i */, RegMetaEntry<E, W> entry) {
    (*regMeta)[std::make_pair(entry.GetOffset(), entry.GetSize())] =
        entry.GetName();
    return 0;
  }

  template <typename Entry>
  int operator()(size_t /* i */, Entry /* entry */) {
    proceed = false;
    return 0;
  }

  RegMeta* regMeta;
  bool proceed;
};

template <Endianness _E, typename _W>
class Trace : public TraceBase {
 public:
  static constexpr Endianness E = _E;
  using W = _W;
  friend class SourceDumper<E, W>;

  Trace(void* data, size_t length)
      : data_(static_cast<std::uint8_t*>(data)),
        length_(length),
        cur_(data_),
        end_(cur_ + length_),
        entryIndex_(0),
        header_(cur_),
        insnIndexStepShift_(static_cast<size_t>(-1)),
        mmapFileOffset_(0) {}
  virtual ~Trace() { munmap(data_, length_); }

  int Init() {
    if ((dwfl_ = DwflBegin()) == nullptr) return -EINVAL;
    symbolIndex_.reset(new SymbolIndex(dwfl_.get()));
    if (!Have(HeaderEntry<E, W>::kFixedLength)) return -EINVAL;
    if (!Advance(header_.GetTlv().GetAlignedLength())) return -EINVAL;
    ScopedRewind scopedRewind(this);
    HeaderVisitor visitor(&regMeta_);
    TraceFilterNoOp filter;
    int err;
    while (cur_ != end_ && visitor.proceed)
      if ((err = VisitOne(&visitor, filter)) < 0) return err;
    return 0;
  }

  template <typename V>
  int InitVisitor(V* visitor) {
    // On average, one executed instruction takes 132.7 bytes in the trace
    // file.
    return visitor->Init(header_, length_ / 128);
  }

  template <typename V, typename F>
  int VisitAll(V* visitor, const F& filter) {
    int err;
    if ((err = InitVisitor(visitor)) < 0) return err;
    while (cur_ != end_)
      if ((err = VisitOne(visitor, filter)) < 0) return err;
    if ((err = visitor->Complete()) < 0) return err;
    return 0;
  }

  template <typename V>
  int VisitAll(V* visitor) {
    if (filter_ == nullptr)
      return VisitAll(visitor, TraceFilterNoOp());
    else
      return VisitAll(visitor, *filter_);
  }

  template <typename V, typename F>
  int VisitOne(V* visitor, const F& filter) {
    if (PyErr_CheckSignals()) {
      bp::throw_error_already_set();
    }
    if (!Have(Tlv<E, W>::kFixedLength)) return -EINVAL;
    Tlv<E, W> tlv(cur_);
    if (!Have(tlv.GetAlignedLength())) return -EINVAL;
    if (filter.isEntryIndexOk(entryIndex_)) {
      Tag tag = tlv.GetTag();
      if (filter.isTagOk(tag)) {
        int err = 0;
        switch (tag) {
          case Tag::MT_LOAD:
          case Tag::MT_STORE:
          case Tag::MT_REG:
          case Tag::MT_GET_REG:
          case Tag::MT_PUT_REG: {
            LdStEntry<E, W> entry(cur_);
            if (filter.isInsnSeqOk(entry.GetInsnSeq()))
              err = (*visitor)(entryIndex_, entry);
            break;
          }
          case Tag::MT_INSN: {
            InsnEntry<E, W> entry(cur_);
            if (filter.isInsnSeqOk(entry.GetInsnSeq()))
              err = (*visitor)(entryIndex_, entry);
            break;
          }
          case Tag::MT_INSN_EXEC: {
            InsnExecEntry<E, W> entry(cur_);
            if (filter.isInsnSeqOk(entry.GetInsnSeq()))
              err = (*visitor)(entryIndex_, entry);
            break;
          }
          case Tag::MT_GET_REG_NX:
          case Tag::MT_PUT_REG_NX: {
            LdStNxEntry<E, W> entry(cur_);
            if (filter.isInsnSeqOk(entry.GetInsnSeq()))
              err = (*visitor)(entryIndex_, entry);
            break;
          }
          case Tag::MT_MMAP:
            if (filter.isMissingInsnSeqOk())
              err = (*visitor)(entryIndex_, MmapEntry<E, W>(cur_));
            break;
          case Tag::MT_REGMETA:
            if (filter.isMissingInsnSeqOk())
              err = (*visitor)(entryIndex_, RegMetaEntry<E, W>(cur_));
            break;
          default:
            return -EINVAL;
        }
        if (err < 0) return err;
      }
    }
    if (!Advance(tlv.GetAlignedLength())) return -EINVAL;
    entryIndex_++;
    return 0;
  }

  template <typename V>
  int VisitOne(V* visitor) {
    if (filter_ == nullptr)
      return VisitOne(visitor, TraceFilterNoOp());
    else
      return VisitOne(visitor, *filter_);
  }

  Endianness GetEndianness() override { return E; }

  size_t GetWordSize() override { return sizeof(W); }

  MachineType GetMachineType() override { return header_.GetMachineType(); }

  std::uint16_t GetRegsSize() override { return header_.GetRegsSize(); }

  TraceId GetTraceId() override { return header_.GetTraceId(); }

  std::vector<std::uint8_t> GetTraceIdPy() override {
    const TraceId& traceId = header_.GetTraceId();

    return std::vector<std::uint8_t>(traceId.begin(), traceId.end());
  }

  bp::object Next() override {
    while (true) {
      if (cur_ == end_) bp::objects::stop_iteration_error();
      TraceEntry2Py visitor;
      int err = VisitOne(&visitor);
      if (err < 0) throw std::runtime_error("Failed to parse the next entry");
      if (visitor.py != nullptr) return bp::object(bp::ptr(visitor.py));
    }
  }

  [[nodiscard]] int SeekInsn(TraceIndex traceIndex) override {
    Seeker visitor;
    if (HasInsnIndex()) {
      std::uint32_t insnIndexIndex =
          (traceIndex.value - kFirstTraceIndex.value) >> insnIndexStepShift_;
      if (insnIndexIndex >= insnIndex_.size()) return -EINVAL;
      Rewind(insnIndex_[insnIndexIndex]);
      visitor.traceIndex.value =
          kFirstTraceIndex.value + (insnIndexIndex << insnIndexStepShift_);
      if (visitor.traceIndex == traceIndex) return 0;
      visitor.traceIndex.value--;
    } else {
      Rewind();
    }
    while (true) {
      if (cur_ == end_) return -EINVAL;
      std::uint8_t* prev = cur_;
      int err;
      if ((err = VisitOne(&visitor)) < 0) return err;
      if (visitor.traceIndex == traceIndex) {
        cur_ = prev;
        entryIndex_--;
        break;
      }
    }
    return 0;
  }

  int SeekStart() override {
    Rewind();
    return 0;
  }

  int SeekEnd() override {
    if (HasInsnIndex()) Rewind(insnIndex_[insnIndex_.size() - 1]);
    NoOp visitor;
    while (cur_ != end_) {
      int err;
      if ((err = VisitOne(&visitor)) < 0) return err;
    }
    return 0;
  }

  template <typename DefSeeker>
  [[nodiscard]] int SeekDef(TraceIndex traceIndex,
                            std::uint32_t relativeDefIndex, Range<W>* range) {
    int err;
    if ((err = SeekInsn(traceIndex)) < 0) return err;
    DefSeeker visitor;
    while (true) {
      if (cur_ == end_) return -EINVAL;
      std::uint8_t* prev = cur_;
      if ((err = VisitOne(&visitor)) < 0) return err;
      if (visitor.relativeDefIndex == relativeDefIndex) {
        cur_ = prev;
        entryIndex_--;
        break;
      }
    }
    *range = visitor.range;
    return 0;
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

  bool HasInsnIndex() override {
    return insnIndexStepShift_ != static_cast<size_t>(-1);
  }

  int BuildInsnIndex(const char* path, size_t stepShift) override {
    if (HasInsnIndex()) return -EINVAL;
    int err;
    PathWithPlaceholder indexPath;
    if ((err = indexPath.Init(path, "index")) < 0) return err;
    if ((err = insnIndex_.Init(indexPath.Get("data").c_str(),
                               InitMode::CreatePersistent)) < 0)
      return err;
    if ((err = mmapIndex_.Init(indexPath.Get("mmap").c_str(),
                               InitMode::CreatePersistent)) < 0)
      return err;
    size_t stepMask = (1 << stepShift) - 1;
    ScopedRewind scopedRewind(this);
    Rewind();
    Indexer visitor;
    TraceIndex prevTraceIndex = visitor.seeker.traceIndex;
    while (cur_ != end_) {
      std::uint8_t* prev = cur_;
      if ((err = VisitOne(&visitor)) < 0) return err;
      if (visitor.seeker.traceIndex != prevTraceIndex) {
        if (((visitor.seeker.traceIndex.value - kFirstTraceIndex.value) &
             stepMask) == 0)
          insnIndex_.push_back(InsnIndexEntry{static_cast<size_t>(prev - data_),
                                              entryIndex_ - 1});
        prevTraceIndex = visitor.seeker.traceIndex;
      }
      if (visitor.isMmap)
        mmapIndex_.push_back(MmapIndexEntry{static_cast<size_t>(prev - data_)});
    }
    InsnIndexHeader header;
    header.traceId = header_.GetTraceId();
    header.stepShift = static_cast<std::uint8_t>(stepShift);
    if ((err = WriteHeader(indexPath.Get("header").c_str(), header)) < 0)
      return err;
    insnIndexStepShift_ = stepShift;
    return 0;
  }

  [[nodiscard]] int LoadInsnIndex(const char* path) override {
    int err;
    if (HasInsnIndex()) return -EINVAL;
    PathWithPlaceholder indexPath;
    if ((err = indexPath.Init(path, "index")) < 0) return err;
    InsnIndexHeader header;
    if ((err = ReadHeader(indexPath.Get("header").c_str(), &header)) < 0)
      return err;
    if (header.traceId != header_.GetTraceId()) return -EINVAL;
    if ((err = insnIndex_.Init(indexPath.Get("data").c_str(),
                               InitMode::OpenExisting)) < 0)
      return err;
    if ((err = mmapIndex_.Init(indexPath.Get("mmap").c_str(),
                               InitMode::OpenExisting)) < 0)
      return err;
    insnIndexStepShift_ = header.stepShift;
    return 0;
  }

  class ScopedRewind {
   public:
    explicit ScopedRewind(Trace* trace)
        : trace_(trace),
          saved_({static_cast<size_t>(trace->cur_ - trace->data_),
                  trace->entryIndex_}) {}
    ScopedRewind(const ScopedRewind&) = delete;
    ~ScopedRewind() { trace_->Rewind(saved_); }

   private:
    Trace* trace_;
    InsnIndexEntry saved_;
  };

  int Dump(const char* path, DumpKind kind, bool header,
           bool summary) override {
    FILE* f = fopen(path, "w");
    if (f == nullptr) return -errno;
    int err;
    switch (kind) {
      case DumpKind::Raw: {
        Dumper<E, W> dumper(f, this, header, summary);
        err = VisitAll(&dumper);
        break;
      }
      case DumpKind::Source: {
        SourceDumper<E, W> dumper(f, this);
        err = VisitAll(&dumper);
        break;
      }
      default:
        err = -EINVAL;
        break;
    }
    if (fclose(f) == EOF && err == 0) err = -errno;
    return err;
  }

  void SetFilter(std::shared_ptr<TraceFilter> filter) override {
    filter_ = std::move(filter);
  }

  const char* GetRegName(std::uint16_t offset, std::uint16_t size) override {
    RegMeta::const_iterator it = regMeta_.find(std::make_pair(offset, size));
    if (it == regMeta_.end())
      return nullptr;
    else
      return it->second;
  }

  LinePy Symbolize(std::uint64_t addr) override {
    if (UpdateDwfl() < 0) return LinePy();
    return FindAddr(dwfl_.get(), addr);
  }

  bp::object Resolve(const char* symbol) override {
    if (UpdateDwfl() < 0) return bp::object();
    if (boost::optional<GElf_Addr> addr = symbolIndex_->Find(symbol))
      return bp::object(*addr);
    else
      return bp::object();
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

  size_t FindMmapFileOffset(size_t fileOffset) const {
    MmVector<MmapIndexEntry>::const_iterator it =
        std::upper_bound(mmapIndex_.begin(), mmapIndex_.end(), fileOffset,
                         [](size_t fileOffset, const MmapIndexEntry& entry) {
                           return fileOffset < entry.fileOffset;
                         });
    if (it == mmapIndex_.begin()) return 0;
    --it;
    return it->fileOffset;
  }

  struct ElfInfo {
    ElfInfo() : base(0), isLoaded(false), needsOpen(true), fd(-1) {}
    ElfInfo(const ElfInfo&) = delete;
    ~ElfInfo() {
      if (fd != -1) close(fd);
    }

    W base;
    bool isLoaded;
    bool needsOpen;
    int fd;
  };

  using Elves = std::map<std::string, ElfInfo>;

  void UpdateElves(size_t mmapFileOffset) {
    for (typename Elves::value_type& elf : elves_) elf.second.isLoaded = false;
    for (size_t i = 0, size = mmapIndex_.size();
         i < size && mmapIndex_[i].fileOffset <= mmapFileOffset; i++) {
      MmapEntry<E, W> entry(data_ + mmapIndex_[i].fileOffset);
      const char* name = entry.GetValue();
      if (*name == 0 || *name == '[') continue;
      ElfInfo& elfInfo = elves_[name];
      if (elfInfo.isLoaded) {
        elfInfo.base = std::min(elfInfo.base, entry.GetStart());
      } else {
        elfInfo.base = entry.GetStart();
        if (elfInfo.needsOpen) {
          elfInfo.fd = open(name, O_RDONLY);
          elfInfo.needsOpen = false;
        }
        elfInfo.isLoaded = true;
      }
    }
  }

  int UpdateDwfl() {
    if (!HasInsnIndex()) return -EINVAL;
    size_t mmapFileOffset = FindMmapFileOffset(cur_ - data_);
    if (mmapFileOffset == mmapFileOffset_) return 0;
    UpdateElves(mmapFileOffset);
    dwfl_report_begin(dwfl_.get());
    for (typename Elves::value_type& elf : elves_)
      if (elf.second.isLoaded && elf.second.fd != -1)
        dwfl_report_elf(dwfl_.get(), elf.first.c_str(), elf.first.c_str(),
                        elf.second.fd, elf.second.base, false);
    if (dwfl_report_end(dwfl_.get(), nullptr, nullptr) != 0) return -EINVAL;
    mmapFileOffset_ = mmapFileOffset;
    symbolIndex_.reset(new SymbolIndex(dwfl_.get()));
    return 0;
  }

  std::uint8_t* data_;
  size_t length_;
  std::uint8_t* cur_;
  std::uint8_t* end_;
  size_t entryIndex_;
  HeaderEntry<E, W> header_;
  MmVector<InsnIndexEntry> insnIndex_;
  MmVector<MmapIndexEntry> mmapIndex_;
  size_t insnIndexStepShift_;
  std::shared_ptr<TraceFilter> filter_;
  RegMeta regMeta_;
  DwflPtr dwfl_;
  size_t mmapFileOffset_;
  Elves elves_;
  std::unique_ptr<SymbolIndex> symbolIndex_;
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

template <Endianness E, typename W>
TraceBase* LoadHelper(std::uint8_t* data, size_t length) {
  int err;
  Trace<E, W>* trace = new Trace<E, W>(data, length);
  if ((err = trace->Init()) < 0) {
    delete trace;
    return nullptr;
  }
  return trace;
}

TraceBase* TraceBase::Load(const char* path) {
  std::uint8_t* data = nullptr;
  size_t length = -1;
  if (MmapFile(path, 2, &data, &length) < 0) return nullptr;
  switch (data[0] << 8 | data[1]) {
    case 'M' << 8 | '4':
      return LoadHelper<Endianness::Big, std::uint32_t>(data, length);
    case 'M' << 8 | '8':
      return LoadHelper<Endianness::Big, std::uint64_t>(data, length);
    case '4' << 8 | 'M':
      return LoadHelper<Endianness::Little, std::uint32_t>(data, length);
    case '8' << 8 | 'M':
      return LoadHelper<Endianness::Little, std::uint64_t>(data, length);
    default:
      munmap(data, length);
      return nullptr;
  }
}

template <typename V>
void TraceBase::Downcast(std::shared_ptr<TraceBase> trace, const V& v) {
  switch (trace->GetEndianness()) {
    case Endianness::Little:
      switch (trace->GetWordSize()) {
        case 4:
          v(std::static_pointer_cast<Trace<Endianness::Little, std::uint32_t>>(
              trace));
          break;
        case 8:
          v(std::static_pointer_cast<Trace<Endianness::Little, std::uint64_t>>(
              trace));
          break;
        default:
          __builtin_unreachable();
      }
      break;
    case Endianness::Big:
      switch (trace->GetWordSize()) {
        case 4:
          v(std::static_pointer_cast<Trace<Endianness::Big, std::uint32_t>>(
              trace));
          break;
        case 8:
          v(std::static_pointer_cast<Trace<Endianness::Big, std::uint64_t>>(
              trace));
          break;
        default:
          __builtin_unreachable();
      }
      break;
    default:
      __builtin_unreachable();
  }
}  // namespace

template <typename W>
struct Def {};

template <typename W>
struct InsnInCode {
  W pc;
  std::uint32_t textIndex;
  std::uint32_t textSize;
};

DEFINE_IDENTIFIER(RegUseIndex, std::uint32_t);
DEFINE_IDENTIFIER(MemUseIndex, std::uint32_t);

struct InsnInTrace {
  InsnSeq insnSeq;
  RegUseIndex regUseStartIndex;
  MemUseIndex memUseStartIndex;
  RegDefIndex regDefStartIndex;
  MemDefIndex memDefStartIndex;
  std::uint8_t regUseCount;
  std::uint8_t memUseCount;
  std::uint8_t regDefCount;
  std::uint8_t memDefCount;
};

template <typename T, typename W>
struct UdTraits {};
template <typename W>
struct UdTraits<RegDefIndex, W> {
  using DefSeeker = RegDefSeeker<W>;
  static constexpr RegDefIndex InsnInTrace::*StartDefIndex =
      &InsnInTrace::regDefStartIndex;
};
template <typename W>
struct UdTraits<MemDefIndex, W> {
  using DefSeeker = MemDefSeeker<W>;
  static constexpr MemDefIndex InsnInTrace::*StartDefIndex =
      &InsnInTrace::memDefStartIndex;
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

template <typename W, typename UseIndex>
struct PartialUse {
  static constexpr UseIndex kFreeSlot{
      static_cast<typename UseIndex::value_type>(-1)};

  UseIndex useIndex;
  Range<W> range;
};

template <typename W, typename UseIndex>
const PartialUse<W, UseIndex>* ScanPartialUses(
    const PartialUse<W, UseIndex>* partialUses, size_t partialUseCount,
    UseIndex useIndex) {
  for (size_t entryIndex = 0; entryIndex < partialUseCount; entryIndex++) {
    const PartialUse<W, UseIndex>& partialUse = partialUses[entryIndex];
    if (partialUse.useIndex == useIndex ||
        partialUse.useIndex == PartialUse<W, UseIndex>::kFreeSlot)
      return &partialUse;
  }
  return nullptr;
}

template <typename W, typename UseIndex>
const PartialUse<W, UseIndex>& FindPartialUse(
    const PartialUse<W, UseIndex>* hashTable, size_t hashTableSize,
    UseIndex useIndex) {
  size_t entryIndex = useIndex.value % hashTableSize;
  const PartialUse<W, UseIndex>* use = ScanPartialUses(
      hashTable + entryIndex, hashTableSize - entryIndex, useIndex);
  if (use == nullptr) use = ScanPartialUses(hashTable, entryIndex, useIndex);
  assert(use != nullptr);
  return *use;
}

template <typename W, typename UseIndex>
class PartialUses {
 public:
  using const_iterator = const PartialUse<W, UseIndex>*;

  PartialUses() : load_(0), maxLoad_(0) {}

  [[nodiscard]] int Init(const char* path, InitMode mode) {
    path_ = path;
    int err;
    if ((err = entries_.Init(path, mode)) < 0) return err;
    if (mode != InitMode::OpenExisting) {
      entries_.resize(11);
      for (size_t i = 0; i < entries_.size(); i++)
        entries_[i].useIndex = PartialUse<W, UseIndex>::kFreeSlot;
    }
    maxLoad_ = entries_.size() / 2;
    return 0;
  }

  PartialUse<W, UseIndex>* end() const { return nullptr; }

  Range<W>& operator[](UseIndex useIndex) {
    PartialUse<W, UseIndex>& result1 = const_cast<PartialUse<W, UseIndex>&>(
        FindPartialUse(entries_.data(), entries_.size(), useIndex));
    if (result1.useIndex == useIndex) return result1.range;
    result1.useIndex = useIndex;
    load_ += 1;
    if (load_ <= maxLoad_) return result1.range;
    reserve(load_ * 2);
    PartialUse<W, UseIndex>& result2 = const_cast<PartialUse<W, UseIndex>&>(
        FindPartialUse(entries_.data(), entries_.size(), useIndex));
    assert(result2.useIndex == useIndex);
    return result2.range;
  }

  const PartialUse<W, UseIndex>* find(UseIndex useIndex) const {
    const PartialUse<W, UseIndex>& result =
        FindPartialUse(entries_.data(), entries_.size(), useIndex);
    return result.useIndex == useIndex ? &result : nullptr;
  }

  const MmVector<PartialUse<W, UseIndex>>& GetData() const { return entries_; }

  void reserve(size_t n) {
    size_t newSize = GetFirstPrimeGreaterThanOrEqualTo(n * 2);
    MmVector<PartialUse<W, UseIndex>> oldEntries;
    if (oldEntries.Init(path_.c_str(), InitMode::CreateTemporary) < 0)
      throw std::bad_alloc();
    oldEntries.insert(oldEntries.end(), entries_.begin(), entries_.end());
    size_t oldSize = entries_.size();
    entries_.resize(newSize);
    for (size_t i = 0; i < newSize; i++)
      entries_[i].useIndex = PartialUse<W, UseIndex>::kFreeSlot;
    for (size_t oldEntryIndex = 0; oldEntryIndex < oldSize; oldEntryIndex++) {
      const PartialUse<W, UseIndex>& oldEntry = oldEntries[oldEntryIndex];
      if (oldEntry.useIndex == PartialUse<W, UseIndex>::kFreeSlot) continue;
      PartialUse<W, UseIndex>& newEntry = const_cast<PartialUse<W, UseIndex>&>(
          FindPartialUse(entries_.data(), newSize, oldEntry.useIndex));
      assert((newEntry.useIndex == PartialUse<W, UseIndex>::kFreeSlot));
      newEntry = oldEntry;
    }
    maxLoad_ = newSize / 2;
  }

 private:
  MmVector<PartialUse<W, UseIndex>> entries_;
  size_t load_;
  size_t maxLoad_;
  std::string path_;
};

template <typename W>
struct ResolvedUse {
  Range<W> range;
  TraceIndex traceIndex;
};

template <typename W, typename UseIndex, typename DefIndex>
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
      UseIndex useIndex{
          static_cast<typename UseIndex::value_type>(uses_.size())};
      uses_.push_back(it->second.defIndex);
      W maxStartAddr = std::max(startAddr, it->second.startAddr);
      W minEndAddr = std::min(endAddr, it->first);
      if (it->second.defRange.startAddr != maxStartAddr ||
          it->second.defRange.endAddr != minEndAddr)
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
      W entryEndAddr = entry.first;
      if (startAddr <= entry.second.startAddr) {
        if (endAddr < entryEndAddr) {
          // Left overlap.
          addressSpace_[entryEndAddr] = entry.second.WithStartAddr(endAddr);
        } else {
          // Outer overlap.
        }
      } else {
        if (endAddr < entryEndAddr) {
          // Inner overlap.
          addressSpace_[startAddr] = entry.second;
          addressSpace_[entryEndAddr] = entry.second.WithStartAddr(endAddr);
        } else {
          // Right overlap.
          addressSpace_[startAddr] = entry.second;
        }
      }
    }
    AddDef(startAddr, endAddr);
    return 0;
  }

  size_t GetUseCount() const { return uses_.size(); }
  size_t GetDefCount() const { return defs_.size(); }
  size_t GetPartialUseCount() const { return partialUses_.GetData().size(); }

  template <Endianness E>
  [[nodiscard]] int DumpUses(FILE* f, UseIndex startIndex, UseIndex endIndex,
                             const MmVector<InsnInTrace>& trace,
                             Trace<E, W>* fullTrace) const {
    for (UseIndex useIndex = startIndex; useIndex < endIndex;
         useIndex.value++) {
      ResolvedUse<W> use;
      int err;
      if ((err = ResolveUse<E>(&use, useIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f,
                   useIndex == startIndex
                       ? "0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIuTraceIndex "]"
                       : ", 0x%" PRIx64 "-0x%" PRIx64 "@[%" PRIuTraceIndex "]",
                   static_cast<std::uint64_t>(use.range.startAddr),
                   static_cast<std::uint64_t>(use.range.endAddr),
                   use.traceIndex.value);
    }
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int DumpDefs(FILE* f, DefIndex startIndex, DefIndex endIndex,
                             const MmVector<InsnInTrace>& trace,
                             Trace<E, W>* fullTrace) const {
    for (DefIndex defIndex = startIndex; defIndex < endIndex;
         defIndex.value++) {
      Range<W> defRange;
      int err;
      if ((err = GetDefRange<E>(&defRange, defIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f,
                   defIndex == startIndex ? "0x%" PRIx64 "-0x%" PRIx64
                                          : ", 0x%" PRIx64 "-0x%" PRIx64,
                   static_cast<std::uint64_t>(defRange.startAddr),
                   static_cast<std::uint64_t>(defRange.endAddr));
    }
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int DumpUsesDot(std::FILE* f, TraceIndex traceIndex,
                                UseIndex startIndex, UseIndex endIndex,
                                const MmVector<InsnInTrace>& trace,
                                Trace<E, W>* fullTrace,
                                const char* prefix) const {
    for (UseIndex useIndex = startIndex; useIndex < endIndex;
         useIndex.value++) {
      ResolvedUse<W> use;
      int err;
      if ((err = ResolveUse<E>(&use, useIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f,
                   "    %" PRIuTraceIndex " -> %" PRIuTraceIndex
                   " [label=\"%s0x%" PRIx64 "-0x%" PRIx64 "\"]\n",
                   traceIndex.value, use.traceIndex.value, prefix,
                   static_cast<std::uint64_t>(use.range.startAddr),
                   static_cast<std::uint64_t>(use.range.endAddr));
    }
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int DumpUsesHtml(std::FILE* f, UseIndex startIndex,
                                 UseIndex endIndex,
                                 const MmVector<InsnInTrace>& trace,
                                 Trace<E, W>* fullTrace,
                                 const char* prefix) const {
    for (UseIndex useIndex = startIndex; useIndex < endIndex;
         useIndex.value++) {
      ResolvedUse<W> use;
      int err;
      if ((err = ResolveUse<E>(&use, useIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f,
                   "            <a href=\"#%" PRIuTraceIndex "\">%s0x%" PRIx64
                   "-0x%" PRIx64 "</a>\n",
                   use.traceIndex.value, prefix,
                   static_cast<std::uint64_t>(use.range.startAddr),
                   static_cast<std::uint64_t>(use.range.endAddr));
    }
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int DumpDefsHtml(std::FILE* f, DefIndex startIndex,
                                 DefIndex endIndex,
                                 const MmVector<InsnInTrace>& trace,
                                 Trace<E, W>* fullTrace,
                                 const char* prefix) const {
    for (DefIndex defIndex = startIndex; defIndex < endIndex;
         defIndex.value++) {
      Range<W> defRange;
      int err;
      if ((err = GetDefRange<E>(&defRange, defIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f, "            %s0x%" PRIx64 "-0x%" PRIx64 "\n", prefix,
                   static_cast<std::uint64_t>(defRange.startAddr),
                   static_cast<std::uint64_t>(defRange.endAddr));
    }
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int DumpUsesCsv(std::FILE* f, TraceIndex traceIndex,
                                UseIndex startIndex, UseIndex endIndex,
                                const MmVector<InsnInTrace>& trace,
                                Trace<E, W>* fullTrace,
                                const char* prefix) const {
    for (UseIndex useIndex = startIndex; useIndex < endIndex;
         useIndex.value++) {
      ResolvedUse<W> use;
      int err;
      if ((err = ResolveUse<E>(&use, useIndex, trace, fullTrace)) < 0)
        return err;
      std::fprintf(f,
                   "%" PRIuTraceIndex ",%" PRIuTraceIndex ",%s,%" PRIu64
                   ",%" PRIu64 "\n",
                   traceIndex.value, use.traceIndex.value, prefix,
                   static_cast<std::uint64_t>(use.range.startAddr),
                   static_cast<std::uint64_t>(use.range.endAddr));
    }
    return 0;
  }

  void AddDef(W startAddr, W endAddr) {
    DefIndex defIndex{static_cast<typename DefIndex::value_type>(defs_.size())};
    defs_.emplace_back();
    addressSpace_[endAddr] = EntryValue{
        startAddr,
        defIndex,
        {startAddr, endAddr},
    };
  }

  TraceIndex GetTraceForDef(DefIndex defIndex,
                            const MmVector<InsnInTrace>& trace) const {
    MmVector<InsnInTrace>::const_iterator it = std::upper_bound(
        trace.begin(), trace.end(), defIndex,
        [](DefIndex defIndex, const InsnInTrace& trace) -> bool {
          return defIndex < trace.*UdTraits<DefIndex, W>::StartDefIndex;
        });
    --it;
    return TraceIndex{static_cast<TraceIndex::value_type>(it - trace.begin())};
  }

  template <Endianness E>
  [[nodiscard]] int ResolveUse(ResolvedUse<W>* use, UseIndex useIndex,
                               const MmVector<InsnInTrace>& trace,
                               Trace<E, W>* fullTrace) const {
    DefIndex defIndex = uses_[useIndex.value];
    Range<W> defRange;
    const PartialUse<W, UseIndex>& partialUse = FindPartialUse(
        partialUses_.GetData().data(), partialUses_.GetData().size(), useIndex);
    if (partialUse.useIndex == PartialUse<W, UseIndex>::kFreeSlot) {
      int err;
      if ((err = GetDefRange<E>(&defRange, defIndex, trace, fullTrace)) < 0)
        return err;
    } else {
      defRange = partialUse.range;
    }
    TraceIndex traceIndex = GetTraceForDef(defIndex, trace);
    *use = ResolvedUse<W>{defRange, traceIndex};
    return 0;
  }

  template <Endianness E>
  [[nodiscard]] int GetDefRange(Range<W>* range, DefIndex defIndex,
                                const MmVector<InsnInTrace>& trace,
                                Trace<E, W>* fullTrace) const {
    if (defIndex.value == 0) {
      *range = Range<W>{0, std::numeric_limits<W>::max()};
      return 0;
    }
    TraceIndex traceIndex = GetTraceForDef(defIndex, trace);
    typename Trace<E, W>::ScopedRewind scopedRewind(fullTrace);
    return fullTrace
        ->template SeekDef<typename UdTraits<DefIndex, W>::DefSeeker>(
            traceIndex,
            defIndex.value -
                (trace[traceIndex.value].*UdTraits<DefIndex, W>::StartDefIndex)
                    .value,
            range);
  }

 private:
  MmVector<DefIndex> uses_;
  // On average, 4% register and 12% memory uses are partial.
  PartialUses<W, UseIndex> partialUses_;
  MmVector<Def<W>> defs_;
  struct EntryValue {
    W startAddr;
    DefIndex defIndex;
    Range<W> defRange;

    EntryValue WithStartAddr(W newStartAddr) const {
      return EntryValue{newStartAddr, defIndex, defRange};
    }
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
  TraceId traceId;
  std::uint8_t hostEndianness;
  std::uint8_t hostWordSize;
  MachineType machineType;  // Traced program machine type.
};

class UdBase {
 public:
  static UdBase* Analyze(const char* path, std::shared_ptr<TraceBase> trace,
                         const char* log);
  static UdBase* Load(const char* path, std::shared_ptr<TraceBase> trace);

  virtual ~UdBase() = default;
  [[nodiscard]] virtual int Init(const BinaryHeader& header) = 0;
  virtual std::vector<InsnSeq> GetCodesForPcRanges(
      const std::vector<Range<std::uint64_t>>& pcRanges) const = 0;
  virtual std::uint64_t GetPcForCode(InsnSeq insnSeq) const = 0;
  virtual std::string GetDisasmForCode(InsnSeq insnSeq) const = 0;
  virtual std::vector<TraceIndex> GetTracesForCode(InsnSeq insnSeq) const = 0;
  virtual InsnSeq GetCodeForTrace(TraceIndex traceIndex) const = 0;
  virtual std::vector<RegUseIndex> GetRegUsesForTrace(
      TraceIndex traceIndex) const = 0;
  virtual std::vector<MemUseIndex> GetMemUsesForTrace(
      TraceIndex traceIndex) const = 0;
  virtual TraceIndex GetTraceForRegUse(RegUseIndex regUse) const = 0;
  virtual TraceIndex GetTraceForMemUse(MemUseIndex memUse) const = 0;
  virtual int DumpDot(const char* dot) const = 0;
  virtual int DumpHtml(const char* html) const = 0;
  virtual int DumpCsv(const char* csv) const = 0;
};

template <Endianness E, typename W>
class Ud : public UdBase {
 public:
  Ud(const char* binary, std::shared_ptr<Trace<E, W>> fullTrace, FILE* f)
      : binary_(binary), fullTrace_(fullTrace), f_(f) {}

  [[nodiscard]] int Init(InitMode mode, MachineType machineType,
                         size_t expectedInsnCount) {
    machineType_ = machineType;

    int err;
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
      InsnSeq insnSeq{static_cast<InsnSeq::value_type>(code_.size())};
      InsnInCode<W>& code = code_.emplace_back();
      code.pc = 0;
      code.textIndex = 0;
      code.textSize = 0;
      disasm_.emplace_back("<unknown>");
      trace_.reserve(expectedInsnCount);
      AddTrace(insnSeq);
      assert(trace_.size() == kFirstTraceIndex.value);
      regState_.AddDef(0, std::numeric_limits<W>::max());
      memState_.AddDef(0, std::numeric_limits<W>::max());
    }

    if ((err = disasmEngine_.Init(machineType, E, sizeof(W))) < 0) return err;

    return 0;
  }

  [[nodiscard]] int Init(const BinaryHeader& header) override {
    return Init(InitMode::OpenExisting, header.machineType, 0);
  }

  [[nodiscard]] int Init(HeaderEntry<E, W> entry, size_t expectedInsnCount) {
    return Init(binary_ == nullptr ? InitMode::CreateTemporary
                                   : InitMode::CreatePersistent,
                entry.GetMachineType(), expectedInsnCount);
  }

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

  int operator()(size_t /* i */, InsnEntry<E, W> entry) {
    if (entry.GetInsnSeq().value != code_.size()) return -EINVAL;
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
    if ((ret = HandleInsnSeq(entry.GetInsnSeq())) < 0) return ret;
    return 0;
  }

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

  int operator()(size_t /* i */, MmapEntry<E, W> /* entry */) { return 0; }

  int operator()(size_t /* i */, RegMetaEntry<E, W> /* entry */) { return 0; }

  int Complete() {
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = DumpBinary()) < 0) return ret;
    return 0;
  }

  std::vector<InsnSeq> GetCodesForPcRanges(
      const std::vector<Range<std::uint64_t>>& pcRanges) const override {
    std::vector<InsnSeq> codes;
    for (InsnSeq insnSeq{0},
         size{static_cast<InsnSeq::value_type>(code_.size())};
         insnSeq < size; insnSeq.value++)
      for (const Range<std::uint64_t>& pcRange : pcRanges) {
        std::uint64_t pc = GetCode(insnSeq).pc;
        if (pc >= pcRange.startAddr && pc <= pcRange.endAddr) {
          codes.push_back(insnSeq);
          break;
        }
      }
    return codes;
  }

  std::uint64_t GetPcForCode(InsnSeq insnSeq) const override {
    return GetCode(insnSeq).pc;
  }

  std::string GetDisasmForCode(InsnSeq insnSeq) const override {
    const InsnInCode<W>& entry = GetCode(insnSeq);
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

  std::vector<TraceIndex> GetTracesForCode(InsnSeq insnSeq) const override {
    std::vector<TraceIndex> traces;
    for (TraceIndex traceIndex{0},
         size{static_cast<TraceIndex::value_type>(trace_.size())};
         traceIndex < size; traceIndex.value++)
      if (GetTrace(traceIndex).insnSeq == insnSeq) traces.push_back(traceIndex);
    return traces;
  }

  InsnSeq GetCodeForTrace(TraceIndex traceIndex) const override {
    return GetTrace(traceIndex).insnSeq;
  }

  std::vector<RegUseIndex> GetRegUsesForTrace(
      TraceIndex traceIndex) const override {
    std::vector<RegUseIndex> regUses;
    for (RegUseIndex
             regUse = GetTrace(traceIndex).regUseStartIndex,
             regUseEndIndex{regUse.value + GetTrace(traceIndex).regUseCount};
         regUse < regUseEndIndex; regUse.value++)
      regUses.push_back(regUse);
    return regUses;
  }

  std::vector<MemUseIndex> GetMemUsesForTrace(
      TraceIndex traceIndex) const override {
    std::vector<MemUseIndex> memUses;
    for (MemUseIndex
             memUse = GetTrace(traceIndex).memUseStartIndex,
             memUseEndIndex{memUse.value + GetTrace(traceIndex).memUseCount};
         memUse < memUseEndIndex; memUse.value++)
      memUses.push_back(memUse);
    return memUses;
  }

  TraceIndex GetTraceForRegUse(RegUseIndex useIndex) const override {
    ResolvedUse<W> use;
    int err;
    if ((err = regState_.template ResolveUse<E>(&use, useIndex, trace_,
                                                fullTrace_.get())) < 0)
      throw std::runtime_error("ResolveUse() failed");
    return use.traceIndex;
  }

  TraceIndex GetTraceForMemUse(MemUseIndex useIndex) const override {
    ResolvedUse<W> use;
    int err;
    if ((err = memState_.template ResolveUse<E>(&use, useIndex, trace_,
                                                fullTrace_.get())) < 0)
      throw std::runtime_error("ResolveUse() failed");
    return use.traceIndex;
  }

 private:
  [[nodiscard]] int Flush() {
    InsnInTrace& trace = trace_.back();
    size_t regUseCount = regState_.GetUseCount() - trace.regUseStartIndex.value;
    size_t memUseCount = memState_.GetUseCount() - trace.memUseStartIndex.value;
    size_t regDefCount = regState_.GetDefCount() - trace.regDefStartIndex.value;
    size_t memDefCount = memState_.GetDefCount() - trace.memDefStartIndex.value;
    if (regUseCount > std::numeric_limits<std::uint8_t>::max() ||
        memUseCount > std::numeric_limits<std::uint8_t>::max() ||
        regDefCount > std::numeric_limits<std::uint8_t>::max() ||
        memDefCount > std::numeric_limits<std::uint8_t>::max())
      return -EINVAL;
    trace.regUseCount = static_cast<std::uint8_t>(regUseCount);
    trace.memUseCount = static_cast<std::uint8_t>(memUseCount);
    trace.regDefCount = static_cast<std::uint8_t>(regDefCount);
    trace.memDefCount = static_cast<std::uint8_t>(memDefCount);

    if (f_ != nullptr) {
      const InsnInCode<W>& code = GetCode(trace.insnSeq);
      std::fprintf(f_, "[%zu]0x%" PRIx64 ": ", trace_.size() - 1,
                   static_cast<std::uint64_t>(code.pc));
      HexDump(f_, &text_[code.textIndex], code.textSize);
      std::fprintf(f_, " %s reg_uses=[", GetDisasm(trace.insnSeq).c_str());
      int err;
      if ((err = regState_.template DumpUses<E>(
               f_, trace.regUseStartIndex,
               RegUseIndex{trace.regUseStartIndex.value + trace.regUseCount},
               trace_, fullTrace_.get())) < 0)
        return err;
      std::fprintf(f_, "] reg_defs=[");
      if ((err = regState_.template DumpDefs<E>(
               f_, trace.regDefStartIndex,
               RegDefIndex{trace.regDefStartIndex.value + trace.regDefCount},
               trace_, fullTrace_.get())) < 0)
        return err;
      std::fprintf(f_, "] mem_uses=[");
      if ((err = memState_.template DumpUses<E>(
               f_, trace.memUseStartIndex,
               MemUseIndex{trace.memUseStartIndex.value + trace.memUseCount},
               trace_, fullTrace_.get())) < 0)
        return err;
      std::fprintf(f_, "] mem_defs=[");
      if ((err = memState_.template DumpDefs<E>(
               f_, trace.memDefStartIndex,
               MemDefIndex{trace.memDefStartIndex.value + trace.memDefCount},
               trace_, fullTrace_.get())) < 0)
        return err;
      std::fprintf(f_, "]\n");
    }

    return 0;
  }

  int AddTrace(InsnSeq insnSeq) {
    InsnInTrace& trace = trace_.emplace_back();
    trace.insnSeq = insnSeq;
    trace.regUseStartIndex.value =
        static_cast<RegUseIndex::value_type>(regState_.GetUseCount());
    trace.memUseStartIndex.value =
        static_cast<MemUseIndex::value_type>(memState_.GetUseCount());
    trace.regDefStartIndex.value =
        static_cast<RegDefIndex::value_type>(regState_.GetDefCount());
    trace.memDefStartIndex.value =
        static_cast<MemDefIndex::value_type>(memState_.GetDefCount());
    return 0;
  }

  int HandleInsnSeq(InsnSeq insnSeq) {
    if (trace_.back().insnSeq == insnSeq) return 0;
    int ret;
    if ((ret = Flush()) < 0) return ret;
    if ((ret = AddTrace(insnSeq)) < 0) return ret;
    return 0;
  }

  int DumpDot(const char* dot) const override {
    std::FILE* f = std::fopen(dot, "w");
    if (f == nullptr) return -errno;
    std::fprintf(f, "digraph ud {\n");
    for (TraceIndex traceIndex{0},
         size{static_cast<TraceIndex::value_type>(trace_.size())};
         traceIndex < size; traceIndex.value++) {
      const InsnInTrace& trace = GetTrace(traceIndex);
      const InsnInCode<W>& code = GetCode(trace.insnSeq);
      std::fprintf(f,
                   "    %" PRIuTraceIndex " [label=\"[%" PRIuTraceIndex
                   "] 0x%" PRIx64 ": %s\"]\n",
                   traceIndex.value, traceIndex.value,
                   static_cast<std::uint64_t>(code.pc),
                   GetDisasm(trace.insnSeq).c_str());
      int err;
      if ((err = regState_.template DumpUsesDot<E>(
               f, traceIndex, trace.regUseStartIndex,
               RegUseIndex{trace.regUseStartIndex.value + trace.regUseCount},
               trace_, fullTrace_.get(), "r")) < 0)
        return err;
      if ((err = memState_.template DumpUsesDot<E>(
               f, traceIndex, trace.memUseStartIndex,
               MemUseIndex{trace.memUseStartIndex.value + trace.memUseCount},
               trace_, fullTrace_.get(), "m")) < 0)
        return err;
    }
    std::fprintf(f, "}\n");
    std::fclose(f);
    return 0;
  }

  int DumpHtml(const char* html) const override {
    std::FILE* f = std::fopen(html, "w");
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
    for (TraceIndex traceIndex{0},
         size{static_cast<TraceIndex::value_type>(trace_.size())};
         traceIndex < size; traceIndex.value++) {
      const InsnInTrace& trace = GetTrace(traceIndex);
      const InsnInCode<W>& code = GetCode(trace.insnSeq);
      std::fprintf(f,
                   "    <tr id=\"%" PRIuTraceIndex
                   "\">\n"
                   "        <td>%" PRIuTraceIndex
                   "</td>\n"
                   "        <td>0x%" PRIx64
                   "</td>\n"
                   "        <td>",
                   traceIndex.value, traceIndex.value,
                   static_cast<std::uint64_t>(code.pc));
      HexDump(f, &text_[code.textIndex], code.textSize);
      std::fprintf(f,
                   "</td>\n"
                   "        <td>");
      HtmlDump(f, GetDisasm(trace.insnSeq).c_str());
      std::fprintf(f,
                   "</td>\n"
                   "        <td>\n");
      int err;
      if ((err = regState_.template DumpUsesHtml<E>(
               f, trace.regUseStartIndex,
               RegUseIndex{trace.regUseStartIndex.value + trace.regUseCount},
               trace_, fullTrace_.get(), "r")) < 0)
        return err;
      if ((err = memState_.template DumpUsesHtml<E>(
               f, trace.memUseStartIndex,
               MemUseIndex{trace.memUseStartIndex.value + trace.memUseCount},
               trace_, fullTrace_.get(), "m")) < 0)
        return err;
      std::fprintf(f,
                   "        </td>\n"
                   "        <td>\n");
      if ((err = regState_.template DumpDefsHtml<E>(
               f, trace.regDefStartIndex,
               RegDefIndex{trace.regDefStartIndex.value + trace.regDefCount},
               trace_, fullTrace_.get(), "r")) < 0)
        return err;
      if ((err = memState_.template DumpDefsHtml<E>(
               f, trace.memDefStartIndex,
               MemDefIndex{trace.memDefStartIndex.value + trace.memDefCount},
               trace_, fullTrace_.get(), "m")) < 0)
        return err;
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
    for (InsnSeq insnSeq{0},
         size{static_cast<InsnSeq::value_type>(code_.size())};
         insnSeq < size; insnSeq.value++) {
      const InsnInCode<W>& code = GetCode(insnSeq);
      std::fprintf(f, "%" PRIuInsnSeq ",%" PRIu64 ",", insnSeq.value,
                   static_cast<std::uint64_t>(GetCode(insnSeq).pc));
      HexDump(f, &text_[code.textIndex], code.textSize);
      std::fprintf(f, ",\"%s\"\n", GetDisasm(insnSeq).c_str());
    }
    std::fclose(f);
    return 0;
  }

  int DumpTraceCsv(const char* path) const {
    std::FILE* f = std::fopen(path, "w");
    if (f == nullptr) return -errno;
    for (TraceIndex traceIndex{0},
         size{static_cast<TraceIndex::value_type>(trace_.size())};
         traceIndex < size; traceIndex.value++)
      std::fprintf(f, "%" PRIuTraceIndex ",%" PRIuInsnSeq "\n",
                   traceIndex.value, GetTrace(traceIndex).insnSeq.value);
    std::fclose(f);
    return 0;
  }

  int DumpUsesCsv(const char* path) const {
    std::FILE* f = std::fopen(path, "w");
    if (f == nullptr) return -errno;
    for (TraceIndex traceIndex{0},
         size{static_cast<TraceIndex::value_type>(trace_.size())};
         traceIndex < size; traceIndex.value++) {
      const InsnInTrace& trace = GetTrace(traceIndex);
      int err;
      if ((err = regState_.template DumpUsesCsv<E>(
               f, traceIndex, trace.regUseStartIndex,
               RegUseIndex{trace.regUseStartIndex.value + trace.regUseCount},
               trace_, fullTrace_.get(), "r")) < 0)
        return err;
      if ((err = memState_.template DumpUsesCsv<E>(
               f, traceIndex, trace.memUseStartIndex,
               MemUseIndex{trace.memUseStartIndex.value + trace.memUseCount},
               trace_, fullTrace_.get(), "m")) < 0)
        return err;
    }
    std::fclose(f);
    return 0;
  }

  int DumpCsv(const char* csv) const override {
    PathWithPlaceholder csvPath;
    int err;
    if ((err = csvPath.Init(csv, "csv")) < 0) return err;
    if ((err = DumpCodeCsv(csvPath.Get("code").c_str())) < 0) return err;
    if ((err = DumpTraceCsv(csvPath.Get("trace").c_str())) < 0) return err;
    if ((err = DumpUsesCsv(csvPath.Get("uses").c_str())) < 0) return err;
    return 0;
  }

  int DumpBinary() const {
    if (binary_ == nullptr) return 0;
    BinaryHeader header;
    header.traceId = fullTrace_->GetTraceId();
    header.hostEndianness = static_cast<std::uint8_t>(kHostEndianness);
    header.hostWordSize = static_cast<std::uint8_t>(kHostWordSize);
    header.machineType = machineType_;
    return WriteHeader(binaryPath_.Get("header").c_str(), header);
  }

  const InsnInCode<W>& GetCode(InsnSeq insnSeq) const {
    return code_[insnSeq.value];
  }

  const std::string& GetDisasm(InsnSeq insnSeq) const {
    return disasm_[insnSeq.value];
  }

  const InsnInTrace& GetTrace(TraceIndex traceIndex) const {
    return trace_[traceIndex.value];
  }

  const char* const binary_;
  std::shared_ptr<Trace<E, W>> fullTrace_;
  FILE* f_;
  MachineType machineType_;
  Disasm disasmEngine_;
  MmVector<InsnInCode<W>> code_;
  MmVector<std::uint8_t> text_;
  std::vector<std::string> disasm_;
  MmVector<InsnInTrace> trace_;
  UdState<W, RegUseIndex, RegDefIndex> regState_;
  UdState<W, MemUseIndex, MemDefIndex> memState_;
  PathWithPlaceholder binaryPath_;
};

int ReadUdHeader(const char* rawPath, BinaryHeader* header) {
  int err;
  PathWithPlaceholder path;
  if ((err = path.Init(rawPath, "binary")) < 0) return err;
  return ReadHeader(path.Get("header").c_str(), header);
}

UdBase* UdBase::Load(const char* rawPath, std::shared_ptr<TraceBase> trace) {
  BinaryHeader header;
  if (ReadUdHeader(rawPath, &header) < 0) return nullptr;
  if (static_cast<Endianness>(header.hostEndianness) != kHostEndianness ||
      static_cast<size_t>(header.hostWordSize) != kHostWordSize ||
      header.traceId != trace->GetTraceId())
    return nullptr;
  UdBase* ud = nullptr;
  TraceBase::Downcast(trace, [rawPath, header, &ud](auto trace) {
    using Trace = typename decltype(trace)::element_type;
    typename Trace::ScopedRewind scopedRewind(trace.get());
    Ud<Trace::E, typename Trace::W>* udW =
        new Ud<Trace::E, typename Trace::W>(rawPath, trace, nullptr);
    if (udW->Init(header) < 0) {
      delete udW;
      return;
    }
    ud = udW;
  });
  return ud;
}

UdBase* UdBase::Analyze(const char* path, std::shared_ptr<TraceBase> trace,
                        const char* log) {
  FILE* f;
  if (log == nullptr) {
    f = nullptr;
  } else {
    f = fopen(log, "w");
    if (f == nullptr) return nullptr;
  }
  UdBase* ud = nullptr;
  TraceBase::Downcast(trace, [&ud, path, f](auto trace) {
    using Trace = typename decltype(trace)::element_type;
    typename Trace::ScopedRewind scopedRewind(trace.get());
    Ud<Trace::E, typename Trace::W>* udW =
        new Ud<Trace::E, typename Trace::W>(path, trace, f);
    if (trace->VisitAll(udW) < 0) {
      delete udW;
      return;
    }
    ud = udW;
  });
  if (log != nullptr) fclose(f);
  return ud;
}

template <Endianness E, typename W>
std::string MangleName(const char* name) {
  return std::string(name) + GetStr(E) + std::to_string(sizeof(W) * 8);
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
      .add_property("value", &InsnEntryPy::CopyValue)
      .add_property("flags", &InsnEntryPy::GetFlags);
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
  using RegMetaEntryPy = RegMetaEntry<E, W, EntryPyEW<E, W>>;
  bp::class_<RegMetaEntryPy, boost::noncopyable, bp::bases<EntryPy>>(
      MangleName<E, W>("RegMetaEntry").c_str(), bp::no_init)
      .add_property("offset", &RegMetaEntryPy::GetOffset)
      .add_property("size", &RegMetaEntryPy::GetSize)
      .add_property("name", &RegMetaEntryPy::CopyName);
}

template <typename T>
void RegisterEnumValues(bp::enum_<T>* /* py */) {}

template <typename T, typename... TT>
void RegisterEnumValues(bp::enum_<T>* py, T t, TT&&... tt) {
  py->value(GetStr(t), t);
  RegisterEnumValues(py, std::forward<TT>(tt)...);
}

template <typename T>
T* CreateIdentifier(typename T::value_type value) {
  return new T{value};
}

template <typename T>
void RegisterIdentifier(const char* name, const char* vectorName) {
  bp::class_<T>(name, bp::no_init)
      .def_readonly("value", &T::value)
      .def("__init__", bp::make_constructor(CreateIdentifier<T>))
      .def("__eq__", &T::operator==)
      .def("__ne__", &T::operator!=)
      .def("__lt__", &T::operator<)  // NOLINT(whitespace/operators)
      .def("__hash__", &T::hash);
  bp::class_<std::vector<T>>(vectorName)
      .def(bp::vector_indexing_suite<std::vector<T>>());
}

}  // namespace

BOOST_PYTHON_MODULE(_memtrace) {
  bp::enum_<Endianness> endianness("Endianness");
  RegisterEnumValues(&endianness, Endianness::Little, Endianness::Big);
  bp::def("get_endianness_str", GetEndiannessStrPy);
  bp::enum_<Tag> tag("Tag");
  tag.value("MT_FIRST", Tag::MT_FIRST);
  tag.value("MT_LAST", Tag::MT_LAST);
  RegisterEnumValues(&tag, Tag::MT_HEADER32, Tag::MT_HEADER64, Tag::MT_LOAD,
                     Tag::MT_STORE, Tag::MT_REG, Tag::MT_INSN, Tag::MT_GET_REG,
                     Tag::MT_PUT_REG, Tag::MT_INSN_EXEC, Tag::MT_GET_REG_NX,
                     Tag::MT_PUT_REG_NX, Tag::MT_MMAP, Tag::MT_REGMETA);
  bp::enum_<MachineType> machineType("MachineType");
  RegisterEnumValues(&machineType, MachineType::X_EM_386,
                     MachineType::X_EM_X86_64, MachineType::X_EM_PPC,
                     MachineType::X_EM_PPC64, MachineType::X_EM_ARM,
                     MachineType::X_EM_AARCH64, MachineType::X_EM_S390,
                     MachineType::X_EM_MIPS, MachineType::X_EM_NANOMIPS);
  bp::class_<EntryPy, boost::noncopyable>("Entry", bp::no_init)
      .def_readonly("index", &EntryPy::index)
      .add_property("tag", &EntryPy::GetTag);
  RegisterEntries<Endianness::Little, std::uint32_t>();
  RegisterEntries<Endianness::Little, std::uint64_t>();
  RegisterEntries<Endianness::Big, std::uint32_t>();
  RegisterEntries<Endianness::Big, std::uint64_t>();
  bp::class_<TagStats>("TagStats", bp::no_init)
      .def_readonly("count", &TagStats::count)
      .def_readonly("size", &TagStats::size);
  bp::class_<std::map<Tag, TagStats>>("std::map<Tag, TagStats>")
      .def(bp::map_indexing_suite<std::map<Tag, TagStats>>());
  bp::class_<Stats>("Stats", bp::no_init)
      .def_readonly("tag_stats", &Stats::tagStats);
  bp::class_<std::vector<std::uint32_t>>("VectorOfU32s")
      .def(bp::vector_indexing_suite<std::vector<std::uint32_t>>());
  bp::class_<TraceFilter>("_TraceFilter", bp::init<>())
      .def_readwrite("first_entry_index", &TraceFilter::firstEntryIndex)
      .def_readwrite("last_entry_index", &TraceFilter::lastEntryIndex)
      .def_readwrite("tag_mask", &TraceFilter::tagMask)
      // There is no set_indexing_suite, so use vectors in the interface.
      .add_property("insn_seqs", &TraceFilter::GetInsnSeqs,
                    &TraceFilter::SetInsnSeqs);
  bp::class_<TraceBase, boost::noncopyable>("_Trace", bp::no_init)
      .def("load", &TraceBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_endianness", &TraceBase::GetEndianness)
      .def("get_word_size", &TraceBase::GetWordSize)
      .def("get_machine_type", &TraceBase::GetMachineType)
      .def("get_regs_size", &TraceBase::GetRegsSize)
      .def("get_trace_id", &TraceBase::GetTraceIdPy)
      .def("__iter__", bp::objects::identity_function())
      .def("__next__", &TraceBase::Next)
      .def("seek_start", &TraceBase::SeekStart)
      .def("seek_insn", &TraceBase::SeekInsn)
      .def("seek_end", &TraceBase::SeekEnd)
      .def("gather_stats", &TraceBase::GatherStats)
      .def("has_insn_index", &TraceBase::HasInsnIndex)
      .def("build_insn_index", &TraceBase::BuildInsnIndex)
      .def("load_insn_index", &TraceBase::LoadInsnIndex)
      .def("dump", &TraceBase::Dump)
      .def("set_filter", &TraceBase::SetFilter)
      .def("get_reg_name", &TraceBase::GetRegName)
      .def("symbolize", &TraceBase::Symbolize)
      .def("resolve", &TraceBase::Resolve);
  bp::class_<std::vector<std::uint8_t>>("std::vector<std::uint8_t>")
      .def(bp::vector_indexing_suite<std::vector<std::uint8_t>>());
  bp::class_<Range<std::uint64_t>>("Range",
                                   bp::init<std::uint64_t, std::uint64_t>())
      .def_readonly("start_addr", &Range<std::uint64_t>::startAddr)
      .def_readonly("end_addr", &Range<std::uint64_t>::endAddr);
  bp::class_<std::vector<Range<std::uint64_t>>>("VectorOfRanges")
      .def(bp::vector_indexing_suite<std::vector<Range<std::uint64_t>>>());
  bp::class_<UdBase, boost::noncopyable>("_Ud", bp::no_init)
      .def("analyze", &UdBase::Analyze,
           bp::return_value_policy<bp::manage_new_object>())
      .def("load", &UdBase::Load,
           bp::return_value_policy<bp::manage_new_object>())
      .staticmethod("load")
      .def("get_codes_for_pc_ranges", &UdBase::GetCodesForPcRanges)
      .def("get_pc_for_code", &UdBase::GetPcForCode)
      .def("get_disasm_for_code", &UdBase::GetDisasmForCode)
      .def("get_traces_for_code", &UdBase::GetTracesForCode)
      .def("get_code_for_trace", &UdBase::GetCodeForTrace)
      .def("get_reg_uses_for_trace", &UdBase::GetRegUsesForTrace)
      .def("get_mem_uses_for_trace", &UdBase::GetMemUsesForTrace)
      .def("get_trace_for_reg_use", &UdBase::GetTraceForRegUse)
      .def("get_trace_for_mem_use", &UdBase::GetTraceForMemUse)
      .def("dump_dot", &UdBase::DumpDot)
      .def("dump_html", &UdBase::DumpHtml)
      .def("dump_csv", &UdBase::DumpCsv);
  bp::class_<Disasm, boost::noncopyable>("Disasm", bp::no_init)
      .def("__init__", bp::make_constructor(CreateDisasm))
      .def("disasm_str", &Disasm::DisasmStr);
  bp::class_<LinePy>("Line", bp::no_init)
      .def_readonly("symbol", &LinePy::symbol)
      .def_readonly("offset", &LinePy::offset)
      .def_readonly("section", &LinePy::section)
      .def_readonly("file", &LinePy::file)
      .def_readonly("line", &LinePy::line);
  bp::enum_<DumpKind> dumpKind("DumpKind");
  RegisterEnumValues(&dumpKind, DumpKind::Raw, DumpKind::Source);
  bp::enum_<InsnFlags> insnFlags("InsnFlags");
  RegisterEnumValues(&insnFlags, InsnFlags::MT_INSN_INDIRECT_JUMP);
  RegisterIdentifier<InsnSeq>("InsnSeq", "VectorOfInsnSeqs");
  RegisterIdentifier<TraceIndex>("TraceIndex", "VectorOfTraceIndices");
  RegisterIdentifier<RegUseIndex>("RegUseIndex", "VectorOfRegUseIndices");
  RegisterIdentifier<MemUseIndex>("MemUseIndex", "VectorOfMemUseIndices");
}
