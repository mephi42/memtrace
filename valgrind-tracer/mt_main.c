#include "pub_core_aspacemgr.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuginfo.h"
#include "pub_core_libcfile.h"
#include "pub_core_machine.h"
#include "pub_core_syscall.h"
#include "pub_tool_aspacehl.h"
#include "pub_tool_basics.h"
#include "pub_tool_guest.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_xarray.h"

#include <elf.h>

#include "mt_regs.h"

#if defined(VG_BIGENDIAN)
#define END Iend_BE
#elif defined(VG_LITTLEENDIAN)
#define END Iend_LE
#else
#error "Unknown endianness"
#endif

#if VG_WORDSIZE == 8
typedef ULong UIntPtr;
#define Ity_Ptr Ity_I64
#define Iop_AddPtr Iop_Add64
#define IRConst_UIntPtr IRConst_U64
#define Iop_CmpLTPtr Iop_CmpLT64U
#define MT_MAGIC 0x4d38
#elif VG_WORDSIZE == 4
typedef UInt UIntPtr;
#define Ity_Ptr Ity_I32
#define Iop_AddPtr Iop_Add32
#define IRConst_UIntPtr IRConst_U32
#define Iop_CmpLTPtr Iop_CmpLT32U
#define MT_MAGIC 0x4d34
#else
#error "Unsupported VG_WORDSIZE"
#endif

static IRExpr* mkUIntPtr(UIntPtr val)
{
   return IRExpr_Const(IRConst_UIntPtr(val));
}

static IRExpr* mkPtr(void* ptr)
{
   return mkUIntPtr((UIntPtr)ptr);
}

#define MT_LOAD 0x4d41
#define MT_STORE 0x4d42
#define MT_REG 0x4d43
#define MT_INSN 0x4d44
#define MT_GET_REG 0x4d45
#define MT_PUT_REG 0x4d46
#define MT_INSN_EXEC 0x4d47
#define MT_GET_REG_NX 0x4d48
#define MT_PUT_REG_NX 0x4d49
#define MT_MMAP 0x4d50
#define MT_REGMETA 0x4d51

#define MT_INSN_INDIRECT_JUMP (1 << 0)

#define TRACE_BUFFER_SIZE (1024 * 1024 * 1024)
#define MAX_ENTRY_LENGTH (4 * 1024)
#define ALIGN_UP(p, size) (((p) + ((size) - 1)) & ~((size) - 1))
#define MT_STATIC_ASSERT(expr) (void)VKI_STATIC_ASSERT(expr)
static const HChar traceFileName[] = "memtrace.out";
static Int traceFd;
static UChar* traceStart;
static UChar* trace;
static UChar* traceEnd;
#define AR_MEM (1 << 1)
#define AR_REGS (1 << 2)
#define AR_INSNS (1 << 3)
#define AR_ALL_REGS (1 << 4)
#define AR_DEFAULT (AR_MEM | AR_REGS | AR_INSNS)
typedef struct {
   Addr start;
   Addr end;
   /* combination of AR_* flags */
   UInt flags;
} AddrRange;
#define MAX_PC_RANGES 32
static AddrRange pcRanges[MAX_PC_RANGES];
static UInt nPcRanges;
static UInt syscallInsnSeq;
typedef struct {
   HChar* symbol;
   Addr offset;
} SymbolicAddr;
typedef struct {
   SymbolicAddr start;
   SymbolicAddr end;
   /* combination of AR_* flags */
   UInt flags;
} SymbolicAddrRange;
#define MAX_SYMBOLIC_PC_RANGES 32
static SymbolicAddrRange symbolicPcRanges[MAX_SYMBOLIC_PC_RANGES];
static UInt nSymbolicPcRanges;
static UChar traceId[16];
static Bool traceIdSpecified;

/* Generic entry header. */
struct __attribute__((__packed__)) Tlv {
   UShort tag;
   UShort length;
};

/* Generic entry header combined with instruction sequence number. */
union __attribute__((__packed__)) TlvInsnSeq {
   struct __attribute__((__packed__)) {
      struct Tlv tlv;
      UInt insnSeq;
   };
   ULong packed;
};

/* The first entry. */
struct __attribute__((__packed__)) HeaderEntry {
   struct Tlv tlv;
   UShort e_machine;
   UShort regsSize;
   UChar traceId[16];
};

/* Used for MT_LOAD, MT_STORE, MT_REG, MT_GET_REG, MT_PUT_REG. */
struct __attribute__((__packed__)) LdStEntry {
   union TlvInsnSeq tlvInsnSeq;
   Addr addr;
   UChar value[0];
};

/* Used for MT_INSN. */
struct __attribute__((__packed__)) InsnEntry {
   union TlvInsnSeq tlvInsnSeq;
   Addr pc;
   UChar flags;
   UChar value[0];
};

/* Used for MT_INSN_EXEC. */
struct __attribute__((__packed__)) InsnExecEntry {
   union TlvInsnSeq tlvInsnSeq;
};

/* Used for MT_GET_REG_NX and MT_PUT_REG_NX. */
struct __attribute__((__packed__)) LdStNxEntry {
   union TlvInsnSeq tlvInsnSeq;
   Addr addr;
   UIntPtr size;
};

/* Used for MT_MMAP. */
struct __attribute__((__packed__)) MmapEntry {
   struct Tlv tlv;
#if VG_WORDSIZE == 8
   UInt padding;
#endif
   Addr start;
   Addr end;
   UIntPtr flags;
   ULong offset;
   ULong dev;
   ULong inode;
   UChar value[0];
};

/* Used for MT_REGMETA. */
struct __attribute__((__packed__)) RegMetaEntry {
   struct Tlv tlv;
   UShort offset;
   UShort size;
   UChar name[0];
};

static void flush_trace_buffer(void)
{
   Int traceSize = trace - traceStart;

   VG_(write)(traceFd, traceStart, traceSize);
   VG_(memset)(traceStart, 0, traceSize);
   trace = traceStart;
}

static void store_reg_meta(void)
{
   struct RegMetaEntry* entry;
   SizeT nameLength;
   SizeT i;

   MT_STATIC_ASSERT(sizeof(struct RegMetaEntry) == 8);
   for (i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
      nameLength = VG_(strlen)(regs[i].name);
      entry = (struct RegMetaEntry*)trace;
      entry->tlv.tag = MT_REGMETA;
      entry->tlv.length = sizeof(struct RegMetaEntry) + nameLength + 1;
      entry->offset = regs[i].offset;
      entry->size = regs[i].size;
      VG_(memcpy)(entry->name, regs[i].name, nameLength + 1);
      trace += ALIGN_UP(entry->tlv.length, sizeof(UIntPtr));
   }
}

static void trace_segment(const NSegment* seg)
{
   struct MmapEntry* entry;
   Int alignedEntryLength;
   const HChar* name;
   Int entryLength;
   Int nameLength;

   name = VG_(am_get_filename)(seg);
   if (name == NULL && seg->end == VG_(clstk_end))
      name = "[stack]";
   nameLength = name == NULL ? 1 : VG_(strlen)(name) + 1;
   entryLength = sizeof(struct MmapEntry) + nameLength;
   alignedEntryLength = ALIGN_UP(entryLength, sizeof(UIntPtr));
   tl_assert(alignedEntryLength <= MAX_ENTRY_LENGTH);
   entry = (struct MmapEntry*)trace;
   entry->tlv.tag = MT_MMAP;
   entry->tlv.length = entryLength;
#if VG_WORDSIZE == 8
   entry->padding = 0;
#endif
   entry->start = seg->start;
   entry->end = seg->end;
   entry->flags = (seg->hasR ? 1 : 0) |
                  (seg->hasW ? 2 : 0) |
                  (seg->hasX ? 4 : 0);
   entry->offset = seg->offset;
   entry->dev = seg->dev;
   entry->inode = seg->ino;
   if (nameLength == 1)
      entry->value[0] = 0;
   else
      VG_(memcpy)(entry->value, name, nameLength);
   trace += alignedEntryLength;
   if (trace > traceEnd - MAX_ENTRY_LENGTH)
      flush_trace_buffer();
}

static void trace_segments(void)
{
   const NSegment* seg;
   Addr* segStarts;
   Int nSegStarts;
   Int i;

   segStarts = VG_(get_segment_starts)(SkFileC | SkAnonC | SkShmC,
                                       &nSegStarts);
   for (i = 0; i < nSegStarts; i++) {
      seg = VG_(am_find_nsegment)(segStarts[i]);
      tl_assert(seg);
      trace_segment(seg);
   }
   VG_(free)(segStarts);
}

static Bool resolve_addr(Addr* addr, const SymbolicAddr* symbolic_addr)
{
   SymAVMAs avmas;

   if (symbolic_addr->symbol == NULL) {
      *addr = symbolic_addr->offset;
      return True;
   }
   if (!VG_(lookup_symbol_SLOW)(VG_(current_DiEpoch)(),
                                "*",
                                symbolic_addr->symbol,
                                &avmas))
      return False;
   *addr = avmas.main + symbolic_addr->offset;
   return True;
}

static Bool update_pc_ranges(void)
{
   AddrRange newPcRanges[MAX_PC_RANGES];
   UInt nNewPcRanges = 0;
   SizeT n;
   UInt i;

   VG_(memset)(newPcRanges, 0, sizeof(newPcRanges));
   for (i = 0; i < nSymbolicPcRanges; i++) {
      if (!resolve_addr(&newPcRanges[nNewPcRanges].start,
                        &symbolicPcRanges[i].start))
         continue;
      if (!resolve_addr(&newPcRanges[nNewPcRanges].end,
                        &symbolicPcRanges[i].end))
         continue;
      newPcRanges[nNewPcRanges].flags = symbolicPcRanges[i].flags;
      nNewPcRanges++;
      if (nNewPcRanges == MAX_PC_RANGES)
         break;
   }

   n = sizeof(AddrRange) * nNewPcRanges;
   if (nNewPcRanges == nPcRanges && VG_(memcmp)(pcRanges, newPcRanges, n) == 0)
      return False;

   VG_(memcpy)(pcRanges, newPcRanges, n);
   nPcRanges = nNewPcRanges;
   return True;
}

static void show_pc_ranges(void)
{
   UInt i;

   VG_(umsg)("Traced addresses:\n");
   if (nPcRanges == 0) {
      VG_(umsg)("(none)\n\n");
      return;
   }
   for (i = 0; i < nPcRanges; i++)
      VG_(umsg)("%016llx-%016llx %c%c%c%c\n",
                (ULong)pcRanges[i].start,
                (ULong)pcRanges[i].end,
                (pcRanges[i].flags & AR_MEM) ? 'm' : '-',
                (pcRanges[i].flags & AR_REGS) ? 'r' : '-',
                (pcRanges[i].flags & AR_INSNS) ? 'i' : '-',
                (pcRanges[i].flags & AR_ALL_REGS) ? 'R' : '-');
   VG_(umsg)("\n");
}

static void open_trace_file(void)
{
   struct HeaderEntry* entry;
   SysRes o;

   o = VG_(open)(traceFileName,
                 VKI_O_CREAT | VKI_O_TRUNC | VKI_O_RDWR,
                 0644);
   if (sr_isError(o)) {
      VG_(umsg)("error: can't open '%s'\n", traceFileName);
      VG_(exit)(1);
   }
   traceFd = VG_(safe_fd)(sr_Res(o));
   if (traceFd == -1) {
      VG_(umsg)("error: safe_fd for '%s' failed\n", traceFileName);
      VG_(exit)(1);
   }
   traceStart = VG_(malloc)("mt.trace", TRACE_BUFFER_SIZE);
   trace = traceStart;
   traceEnd = traceStart + TRACE_BUFFER_SIZE;

   MT_STATIC_ASSERT(sizeof(struct HeaderEntry) == 24);
   entry = (struct HeaderEntry*)trace;
   entry->tlv.tag = MT_MAGIC;
   entry->tlv.length = sizeof(struct HeaderEntry);
   entry->e_machine = VG_ELF_MACHINE;
   entry->regsSize = sizeof(VexGuestArchState);
   VG_(memset)(entry->traceId, 0, sizeof(entry->traceId));
   if (traceIdSpecified)
      VG_(memcpy)(entry->traceId, traceId, sizeof(entry->traceId));
   else
      VG_(do_syscall3)(__NR_getrandom,
                       (UWord)entry->traceId, sizeof(entry->traceId), 0);
   trace += sizeof(struct HeaderEntry);

   store_reg_meta();
   trace_segments();
   update_pc_ranges();
   /* Always show the initial ranges. */
   show_pc_ranges();
}

static void close_trace_file(void)
{
   flush_trace_buffer();
   VG_(free)(traceStart);
   VG_(close)(traceFd);
}

static IRTemp load_current_entry_ptr(IRSB* out)
{
   IRTemp currentEntryPtr;
   IRExpr* loadEntryPtr;

   /* currentEntryPtr = trace; */
   currentEntryPtr = newIRTemp(out->tyenv, Ity_Ptr);
   loadEntryPtr = IRExpr_Load(END, Ity_Ptr, mkPtr(&trace));
   addStmtToIRSB(out, IRStmt_WrTmp(currentEntryPtr, loadEntryPtr));
   return currentEntryPtr;
}

static void store_value(IRSB* out,
                        IRTemp currentEntryPtr,
                        Int offset,
                        IRExpr* value)
{
   IRExpr* calculateValuePtr;
   IRTemp valuePtr;
   IRTemp valueTmp;

   /* valuePtr = currentEntryPtr + offset; */
   valuePtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculateValuePtr = IRExpr_Binop(Iop_AddPtr,
                                    IRExpr_RdTmp(currentEntryPtr),
                                    mkUIntPtr(offset));
   addStmtToIRSB(out, IRStmt_WrTmp(valuePtr, calculateValuePtr));
   /* (*(typeof(value)*)valuePtr) = value; */
   valueTmp = newIRTemp(out->tyenv, typeOfIRExpr(out->tyenv, value));
   addStmtToIRSB(out, IRStmt_WrTmp(valueTmp, value));
   addStmtToIRSB(out, IRStmt_Store(END,
                                   IRExpr_RdTmp(valuePtr),
                                   IRExpr_RdTmp(valueTmp)));
}

static void update_current_entry_ptr(IRSB* out,
                                     IRTemp currentEntryPtr,
                                     Int entryLength)
{
   IRTemp updatedEntryPtr;
   IRTemp isFlushNeeded;
   IRExpr* incEntryPtr;
   IRDirty* d;

   tl_assert(entryLength <= MAX_ENTRY_LENGTH);

   /* updatedEntryPtr = currentEntryPtr + entryLength; */
   updatedEntryPtr = newIRTemp(out->tyenv, Ity_Ptr);
   incEntryPtr = IRExpr_Binop(Iop_AddPtr,
                              IRExpr_RdTmp(currentEntryPtr),
                              mkUIntPtr(entryLength));
   addStmtToIRSB(out, IRStmt_WrTmp(updatedEntryPtr, incEntryPtr));
   /* trace = updatedEntryPtr; */
   addStmtToIRSB(out, IRStmt_Store(END,
                                   mkPtr(&trace),
                                   IRExpr_RdTmp(updatedEntryPtr)));
   /* isFlushNeeded = traceEnd - MAX_ENTRY_LENGTH < updatedEntryPtr; */
   isFlushNeeded = newIRTemp(out->tyenv, Ity_I1);
   addStmtToIRSB(out,
                 IRStmt_WrTmp(isFlushNeeded,
                              IRExpr_Binop(Iop_CmpLTPtr,
                                           mkPtr(traceEnd - MAX_ENTRY_LENGTH),
                                           IRExpr_RdTmp(updatedEntryPtr))));
   /* if (isFlushNeeded) flush_trace_buffer(); */
   d = unsafeIRDirty_0_N(0,
                         "flush_trace_buffer",
                         flush_trace_buffer,
                         mkIRExprVec_0());
   d->guard = IRExpr_RdTmp(isFlushNeeded);
   d->mFx   = Ifx_Write;
   d->mAddr = mkPtr(&trace);
   d->mSize = sizeof trace;
   addStmtToIRSB(out, IRStmt_Dirty(d));
}

static void add_ldst_entry(IRSB* out,
                           UInt insnSeq,
                           IRExpr* addr,
                           UShort tag,
                           IRExpr* value)
{
   union TlvInsnSeq tlvInsnSeq;
   IRTemp currentEntryPtr;
   Int valueLength;
   Int entryLength;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct LdStEntry) == 12 :
                    VG_WORDSIZE == 8 ? sizeof(struct LdStEntry) == 16 :
                    0);
   valueLength = sizeofIRType(typeOfIRExpr(out->tyenv, value));
   entryLength = sizeof(struct LdStEntry) + valueLength;
   /* entry = ...; */
   currentEntryPtr = load_current_entry_ptr(out);
   /* entry->tlvInsnSeq = tlvInsnSeq; */
   tlvInsnSeq.packed = 0;
   tlvInsnSeq.tlv.tag = tag;
   tlvInsnSeq.tlv.length = entryLength;
   tlvInsnSeq.insnSeq = insnSeq;
   store_value(out,
               currentEntryPtr,
               offsetof(struct LdStEntry, tlvInsnSeq.packed),
               IRExpr_Const(IRConst_U64(tlvInsnSeq.packed)));
   /* entry->addr = addr; */
   store_value(out,
               currentEntryPtr,
               offsetof(struct LdStEntry, addr),
               addr);
   /* entry->value = value; */
   store_value(out,
               currentEntryPtr,
               offsetof(struct LdStEntry, value),
               value);
   /* trace = ...; */
   update_current_entry_ptr(out,
                            currentEntryPtr,
                            ALIGN_UP(entryLength, sizeof(UIntPtr)));
}

static void add_ldst_entries_now(UShort tag,
                                 UInt insnSeq,
                                 ThreadId tid,
                                 Addr addr,
                                 SizeT size)
{
   while (size > 0) {
      struct LdStEntry* entry = (struct LdStEntry*)trace;
      Int alignedEntryLength;
      Int entryLength;
      SizeT chunkSize;

      chunkSize = MAX_ENTRY_LENGTH - sizeof(struct LdStEntry);
      if (chunkSize > size)
         chunkSize = size;
      entryLength = sizeof(struct LdStEntry) + chunkSize;
      alignedEntryLength = ALIGN_UP(entryLength, sizeof(UIntPtr));
      tl_assert(alignedEntryLength <= MAX_ENTRY_LENGTH);
      entry->tlvInsnSeq.tlv.tag = tag;
      entry->tlvInsnSeq.tlv.length = entryLength;
      entry->tlvInsnSeq.insnSeq = insnSeq;
      entry->addr = addr;
      if (tag == MT_GET_REG || tag == MT_PUT_REG)
         VG_(get_shadow_regs_area)(tid, entry->value, 0, addr, chunkSize);
      else
         VG_(memcpy)(entry->value, (void*)addr, chunkSize);
      trace += alignedEntryLength;
      if (trace > traceEnd - MAX_ENTRY_LENGTH)
         flush_trace_buffer();
      addr += chunkSize;
      size -= chunkSize;
   }
}

static void add_reg_entry(IRSB* out, UInt insnSeq, Int offset)
{
   add_ldst_entry(out,
                  insnSeq,
                  mkUIntPtr(offset),
                  MT_REG,
                  IRExpr_Get(offset, Ity_Ptr));
}

static void add_reg_entries(IRSB* out, UInt insnSeq)
{
   Int i;

   for (i = 0; i < sizeof(VexGuestArchState); i += VG_WORDSIZE)
      add_reg_entry(out, insnSeq, i);
}

static void add_insn_entry_now(UInt insnSeq, Addr pc, UInt insn_length,
                               UChar flags)
{
   struct InsnEntry* entry;
   Int alignedEntryLength;
   Int entryLength;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct InsnEntry) == 13 :
                    VG_WORDSIZE == 8 ? sizeof(struct InsnEntry) == 17 :
                    0);
   entryLength = sizeof(struct InsnEntry) + insn_length;
   entry = (struct InsnEntry*)trace;
   entry->tlvInsnSeq.tlv.tag = MT_INSN;
   entry->tlvInsnSeq.tlv.length = entryLength;
   entry->tlvInsnSeq.insnSeq = insnSeq;
   entry->pc = pc;
   entry->flags = flags;
   VG_(memcpy)(entry->value, (void*)pc, insn_length);
   alignedEntryLength = ALIGN_UP(entryLength, sizeof(UIntPtr));
   tl_assert(alignedEntryLength <= MAX_ENTRY_LENGTH);
   trace += alignedEntryLength;
   if (trace > traceEnd - MAX_ENTRY_LENGTH)
      flush_trace_buffer();
}

static void add_insn_exec_entry(IRSB* out, UInt insnSeq)
{
   IRTemp currentEntryPtr;
   Int entryLength;
   union TlvInsnSeq tlvInsnSeq;

   MT_STATIC_ASSERT(sizeof(struct InsnExecEntry) == 8);
   currentEntryPtr = load_current_entry_ptr(out);
   entryLength = sizeof(struct InsnExecEntry);
   tlvInsnSeq.packed = 0;
   tlvInsnSeq.tlv.tag = MT_INSN_EXEC;
   tlvInsnSeq.tlv.length = entryLength;
   tlvInsnSeq.insnSeq = insnSeq;
   store_value(out,
               currentEntryPtr,
               offsetof(struct InsnExecEntry, tlvInsnSeq.packed),
               IRExpr_Const(IRConst_U64(tlvInsnSeq.packed)));
   update_current_entry_ptr(out, currentEntryPtr, entryLength);
}

static void add_raw_entries_now(XArray* entries)
{
   void* ptr;
   Word n;

   VG_(getContentsXA_UNSAFE)(entries, &ptr, &n);
   if (trace + n + MAX_ENTRY_LENGTH > traceEnd)
      flush_trace_buffer();
   VG_(memcpy)(trace, ptr, n);
   trace += n;
}

static void mt_track_new_mem_mmap(Addr a,
                                  SizeT len,
                                  Bool rr,
                                  Bool ww,
                                  Bool xx,
                                  ULong di_handle)
{
   const NSegment* seg;

   seg = VG_(am_find_nsegment)(a);
   if (seg)
      trace_segment(seg);
   if (update_pc_ranges())
      /* Show ranges only if they are new. */
      show_pc_ranges();
}

static Int get_pc_flags(Addr pc)
{
   Int flags = 0;
   UInt i;

   for (i = 0; i < nPcRanges; i++)
      if (pc >= pcRanges[i].start && pc <= pcRanges[i].end)
         flags |= pcRanges[i].flags;
   return flags;
}

static Bool parse_offset(Addr* value, const HChar* start, const HChar* end)
{
   HChar* endptr;
   ULong tmp;

   tmp = VG_(strtoull10)(start, &endptr);
   if (endptr == end) {
      *value = tmp;
      return True;
   }

   tmp = VG_(strtoull16)(start, &endptr);
   if (endptr == end) {
      *value = tmp;
      return True;
   }

   return False;
}

static const HChar* strchr_range(const HChar* start, const HChar* end, HChar c)
{
   const HChar* p;

   for (p = start; p != end; p++)
      if (*p == c)
         break;
   return p;
}

static HChar* strdup_range(const HChar* start, const HChar* end)
{
   HChar* result;

   result = VG_(malloc)("strdup_range", end - start + 1);
   VG_(memcpy)(result, start, end - start);
   result[end - start] = '\0';
   return result;
}

static Bool parse_addr(SymbolicAddr* addr,
                       const HChar* start,
                       const HChar* end)
{
   const HChar* symbol_end;

   /* Recognize the following combinations:
      - "<number>".
      - "<symbol>".
      - "<symbol>+<number>". */

   if (parse_offset(&addr->offset, start, end)) {
      addr->symbol = NULL;
      return True;
   }

   symbol_end = strchr_range(start, end, '+');
   addr->symbol = strdup_range(start, symbol_end);
   if (symbol_end == end) {
      addr->offset = 0;
   } else {
      if (!parse_offset(&addr->offset, symbol_end + 1, end))
         return False;
   }

   return True;
}

static Bool parse_flags(UInt* flags, const HChar* start, const HChar* end)
{
   const HChar* p;

   *flags = 0;
   for (p = start; p != end; p++) {
      switch (*p) {
      case 'i':
         *flags |= AR_INSNS;
         break;
      case 'm':
         *flags |= AR_MEM;
         break;
      case 'r':
         *flags |= AR_REGS;
         break;
      case 'R':
         *flags |= AR_ALL_REGS;
         break;
      default:
         return False;
      }
   }
   return True;
}

static Bool add_pc_range(const HChar* spec)
{
   SymbolicAddrRange* range;
   const HChar* colon;
   const HChar* dash;
   const HChar* end;

   if (nSymbolicPcRanges == MAX_SYMBOLIC_PC_RANGES)
      return False;
   range = &symbolicPcRanges[nSymbolicPcRanges];

   /* Parse start. */
   dash = VG_(strchr)(spec, '-');
   if (dash == NULL)
      return False;
   if (!parse_addr(&range->start, spec, dash))
      return False;

   /* Parse end. */
   colon = VG_(strchr)(dash, ':');
   end = spec + VG_(strlen)(spec);
   if (!parse_addr(&range->end, dash + 1, colon == NULL ? end : colon))
      return False;

   /* Parse flags. */
   if (colon == NULL) {
      range->flags = AR_DEFAULT;
   } else {
      if (!parse_flags(&range->flags, colon + 1, end))
         return False;
   }

   nSymbolicPcRanges++;
   return True;
}

static Int parse_hex_digit(HChar digit) {
   switch (digit) {
   case '0': return 0;
   case '1': return 1;
   case '2': return 2;
   case '3': return 3;
   case '4': return 4;
   case '5': return 5;
   case '6': return 6;
   case '7': return 7;
   case '8': return 8;
   case '9': return 9;
   case 'a': case 'A': return 10;
   case 'b': case 'B': return 11;
   case 'c': case 'C': return 12;
   case 'd': case 'D': return 13;
   case 'e': case 'E': return 14;
   case 'f': case 'F': return 15;
   default: return -1;
   }
}

static Bool set_trace_id(const HChar *spec)
{
   Int digit;
   SizeT i;

   for (i = 0; i < sizeof(traceId) * 2; i++) {
      digit = parse_hex_digit(spec[i]);
      if (digit == -1)
         return False;

      traceId[i / 2] |= digit << (4 - (i % 2) * 4);
   }

   traceIdSpecified = True;
   return True;
}

static Bool mt_process_cmd_line_option(const HChar* arg)
{
   const HChar* tmpStr;

   if (VG_STR_CLO(arg, "--pc-range", tmpStr))
      return add_pc_range(tmpStr);

   if (VG_STR_CLO(arg, "--trace-id", tmpStr))
      return set_trace_id(tmpStr);

   return False;
}

static void mt_print_usage(void)
{
}

static void mt_print_debug_usage(void)
{
}

static void mt_post_clo_init(void)
{
   if (nSymbolicPcRanges == 0) {
      symbolicPcRanges[0].start.symbol = NULL;
      symbolicPcRanges[0].start.offset = 0;
      symbolicPcRanges[0].end.symbol = NULL;
      symbolicPcRanges[0].end.offset = (Addr)-1;
      symbolicPcRanges[0].flags = AR_DEFAULT;
      nSymbolicPcRanges = 1;
   }

   open_trace_file();
}

static Bool is_ijk_syscall(IRJumpKind ijk)
{
   switch (ijk) {
   case Ijk_Sys_syscall:
   case Ijk_Sys_int32:
   case Ijk_Sys_int128:
   case Ijk_Sys_int129:
   case Ijk_Sys_int130:
   case Ijk_Sys_int145:
   case Ijk_Sys_int210:
   case Ijk_Sys_sysenter:
      return True;
   default:
      return False;
   }
}

static void store_syscall_insn_seq(IRSB* out, UInt insnSeq)
{
   addStmtToIRSB(out,
                 IRStmt_Store(END,
                              mkPtr(&syscallInsnSeq),
                              IRExpr_Const(IRConst_U32(insnSeq))));
}

static Int get_last_mark_idx(IRSB* bb)
{
   Int i, result = -1;

   for (i = 0; i < bb->stmts_used; i++) {
      if (bb->stmts[i]->tag == Ist_IMark)
         result = i;
   }

   return result;
}

static
IRSB* mt_instrument(VgCallbackClosure* closure,
                    IRSB* bb,
                    const VexGuestLayout* layout,
                    const VexGuestExtents* vge,
                    const VexArchInfo* archinfo_host,
                    IRType gWordTy,
                    IRType hWordTy)
{
   static UInt insnSeq = 0;
   Int i, last_mark_idx;
   Int pcFlags = 0;
   IRSB* out;

   last_mark_idx = get_last_mark_idx(bb);
   out = deepCopyIRSBExceptStmts(bb);
   for (i = 0; i < bb->stmts_used; i++) {
      IRStmt* stmt = bb->stmts[i];

      switch (stmt->tag) {
      case Ist_NoOp:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_IMark: {
         Addr pc = stmt->Ist.IMark.addr;

         insnSeq++;
         pcFlags = get_pc_flags(pc);
         if (pcFlags) {
            UChar flags = 0;

            if (i == last_mark_idx && bb->next->tag != Iex_Const)
               /* Ist_Exit.dst is IRConst, so no need to check them. */
               flags |= MT_INSN_INDIRECT_JUMP;
            add_insn_entry_now(insnSeq, pc, stmt->Ist.IMark.len, flags);
         }
         if (pcFlags & AR_INSNS)
            add_insn_exec_entry(out, insnSeq);
         if (pcFlags & AR_ALL_REGS)
            add_reg_entries(out, insnSeq);
         addStmtToIRSB(out, stmt);
         break;
      }
      case Ist_AbiHint:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_Put:
         if (pcFlags & AR_REGS) {
            IRExpr* addr = mkUIntPtr(stmt->Ist.Put.offset);
            IRExpr* data = stmt->Ist.Put.data;

            add_ldst_entry(out, insnSeq, addr, MT_PUT_REG, data);
         }
         addStmtToIRSB(out, stmt);
         break;
      case Ist_PutI:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_WrTmp: {
         IRExpr* data = stmt->Ist.WrTmp.data;

         if ((pcFlags & AR_MEM) && data->tag == Iex_Load) {
            IRExpr* addr = data->Iex.Load.addr;

            add_ldst_entry(out, insnSeq, addr, MT_LOAD, data);
         } else if ((pcFlags & AR_REGS) && data->tag == Iex_Get) {
            IRExpr* addr = mkUIntPtr(data->Iex.Get.offset);

            add_ldst_entry(out, insnSeq, addr, MT_GET_REG, data);
         }
         addStmtToIRSB(out, stmt);
         break;
      }
      case Ist_Store:
         if (pcFlags & AR_MEM) {
            IRExpr* addr = stmt->Ist.Store.addr;
            IRExpr* data = stmt->Ist.Store.data;

            add_ldst_entry(out, insnSeq, addr, MT_STORE, data);
         }
         addStmtToIRSB(out, stmt);
         break;
      case Ist_LoadG:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_StoreG:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_CAS:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_LLSC:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_Dirty:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_MBE:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_Exit: {
         struct LdStNxEntry entry;
         UInt insnSeqNx = insnSeq;
         Int pcFlagsNx = pcFlags;
         XArray* entries;
         IRDirty* d;
         Int j;

         MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct LdStNxEntry) == 16 :
                          VG_WORDSIZE == 8 ? sizeof(struct LdStNxEntry) == 24 :
                          0);
         entries = VG_(newXA)(VG_(malloc),
                              "mt.nx.1",
                              VG_(free),
                              sizeof(UChar));
         for (j = i + 1; j < bb->stmts_used; j++) {
            IRStmt* stmtNx = bb->stmts[j];

            switch (stmtNx->tag) {
            case Ist_IMark: {
               Addr pcNx = stmtNx->Ist.IMark.addr;

               insnSeqNx++;
               pcFlagsNx = get_pc_flags(pcNx);
               break;
            }
            case Ist_Put:
               if (pcFlagsNx & AR_REGS) {
                  IRExpr* data = stmtNx->Ist.Put.data;

                  entry.tlvInsnSeq.packed = 0;
                  entry.tlvInsnSeq.tlv.tag = MT_PUT_REG_NX;
                  entry.tlvInsnSeq.tlv.length = sizeof entry;
                  entry.tlvInsnSeq.insnSeq = insnSeqNx;
                  entry.addr = stmtNx->Ist.Put.offset;
                  entry.size = sizeofIRType(typeOfIRExpr(out->tyenv, data));
                  VG_(addBytesToXA)(entries, &entry, sizeof entry);
               }
               break;
            case Ist_WrTmp: {
               IRExpr* data = stmtNx->Ist.WrTmp.data;

               if ((pcFlagsNx & AR_REGS) && data->tag == Iex_Get) {
                  entry.tlvInsnSeq.packed = 0;
                  entry.tlvInsnSeq.tlv.tag = MT_GET_REG_NX;
                  entry.tlvInsnSeq.tlv.length = sizeof entry;
                  entry.tlvInsnSeq.insnSeq = insnSeqNx;
                  entry.addr = data->Iex.Get.offset;
                  entry.size = sizeofIRType(typeOfIRExpr(out->tyenv, data));
                  VG_(addBytesToXA)(entries, &entry, sizeof entry);
               }
               break;
            }
            default:
               break;
            }
         }

         d = unsafeIRDirty_0_N(0,
                               "add_raw_entries_now",
                               add_raw_entries_now,
                               mkIRExprVec_1(mkPtr(entries)));
         d->guard = stmt->Ist.Exit.guard;
         d->mFx   = Ifx_Write;
         d->mAddr = mkPtr(&trace);
         d->mSize = sizeof trace;
         addStmtToIRSB(out, IRStmt_Dirty(d));

         if (is_ijk_syscall(stmt->Ist.Exit.jk))
            store_syscall_insn_seq(out, insnSeq);

         addStmtToIRSB(out, stmt);
         break;
      }
      default:
         ppIRStmt(stmt);
         tl_assert(0);
      }
   }
   if (is_ijk_syscall(bb->jumpkind))
      store_syscall_insn_seq(out, insnSeq);
   return out;
}

static void mt_track_pre_mem_read(CorePart part,
                                  ThreadId tid,
                                  const HChar* s,
                                  Addr a,
                                  SizeT size)
{
   if (part == Vg_CoreSysCall)
      add_ldst_entries_now(MT_LOAD, syscallInsnSeq, tid, a, size);
}

static void mt_track_pre_mem_read_asciiz(CorePart part,
                                         ThreadId tid,
                                         const HChar* s,
                                         Addr a)
{
   /* Treat this as a 1-byte read for now. */
   mt_track_pre_mem_read(part, tid, s, a, 1);
}

static void mt_track_post_mem_write(CorePart part,
                                    ThreadId tid,
                                    Addr a,
                                    SizeT size)
{
   if (part == Vg_CoreSysCall)
      add_ldst_entries_now(MT_STORE, syscallInsnSeq, tid, a, size);
}

static void mt_track_pre_reg_read(CorePart part,
                                  ThreadId tid,
                                  const HChar* s,
                                  PtrdiffT offset,
                                  SizeT size)
{
   if (part == Vg_CoreSysCall)
      add_ldst_entries_now(MT_GET_REG, syscallInsnSeq, tid, offset, size);
}

static void mt_track_post_reg_write(CorePart part,
                                    ThreadId tid,
                                    PtrdiffT offset,
                                    SizeT size)
{
   if (part == Vg_CoreSysCall)
      add_ldst_entries_now(MT_PUT_REG, syscallInsnSeq, tid, offset, size);
}

static void mt_fini(Int exitcode)
{
   close_trace_file();
}

static void mt_pre_clo_init(void)
{
   VG_(details_name)("Memory Tracer");
   VG_(details_description)("Valgrind tool for tracing memory accesses");
   VG_(details_copyright_author)(
      "Copyright (C) 2019-2025, and GNU GPL'd, by mephi42.");
   VG_(details_bug_reports_to)("https://github.com/mephi42/memtrace");
   VG_(basic_tool_funcs)(mt_post_clo_init,
                         mt_instrument,
                         mt_fini);
   VG_(needs_command_line_options)(mt_process_cmd_line_option,
                                   mt_print_usage,
                                   mt_print_debug_usage);
   /* Valgrind passes an optimized IRSB to mt_instrument, in which nearby
      instructions might be intertwined. Therefore, in order to get the
      accurate association of data accesses to instructions, we need to look at
      one instruction at a time.
      Note: this might not always work, e.g., on x86, call+pop merging ignores
      this setting. */
   VG_(clo_vex_control).guest_max_insns = 1;
   /* Track syscalls. */
   VG_(track_pre_mem_read)(mt_track_pre_mem_read);
   VG_(track_pre_mem_read_asciiz)(mt_track_pre_mem_read_asciiz);
   VG_(track_post_mem_write)(mt_track_post_mem_write);
   VG_(track_pre_reg_read)(mt_track_pre_reg_read);
   VG_(track_post_reg_write)(mt_track_post_reg_write);
   VG_(track_new_mem_mmap)(mt_track_new_mem_mmap);
}

VG_DETERMINE_INTERFACE_VERSION(mt_pre_clo_init)
