#include "pub_core_aspacemgr.h"
#include "pub_core_libcfile.h"
#include "pub_core_machine.h"
#include "pub_tool_aspacehl.h"
#include "pub_tool_basics.h"
#include "pub_tool_guest.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_xarray.h"

#include <elf.h>

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

#define MT_LOAD 0x4c4c
#define MT_STORE 0x5353
#define MT_REG 0x5252
#define MT_INSN 0x4949
#define MT_GET_REG 0x4747
#define MT_PUT_REG 0x5050
#define MT_INSN_EXEC 0x5858
#define MT_GET_REG_NX 0x6767
#define MT_PUT_REG_NX 0x7070
#define MT_MMAP 0x4d4d

#define TRACE_BUFFER_SIZE (1024 * 1024 * 1024)
#define MAX_ENTRY_LENGTH (4 * 1024)
#define ALIGN_UP(p, size) (((p) + ((size) - 1)) & ~((size) - 1))
#define MT_STATIC_ASSERT(expr) (void)VKI_STATIC_ASSERT(expr)
static const HChar trace_file_name[] = "memtrace.out";
static Int trace_fd;
static UChar* trace_start;
static UChar* trace;
static UChar* trace_end;
#define AR_MEM (1 << 1)
#define AR_REGS (1 << 2)
#define AR_INSNS (1 << 3)
#define AR_ALL_REGS (1 << 4)
#define AR_DEFAULT AR_MEM
typedef struct {
   Addr start;
   Addr end;
   /* combination of AR_* flags */
   Int flags;
} AddrRange;
#define MAX_PC_RANGES 32
static AddrRange pc_ranges[MAX_PC_RANGES];
static UInt n_pc_ranges;

/* Generic entry header. */
union Tlv {
   struct {
      UShort tag;
      UShort length;
    };
    UIntPtr packed;
};

/* The first entry. */
struct HeaderEntry {
   union Tlv tlv;
   UShort e_machine;
};

/* Used for MT_LOAD, MT_STORE, MT_REG, MT_GET_REG, MT_PUT_REG. */
struct LdStEntry {
   union Tlv tlv;
   Addr pc;
   Addr addr;
   UChar value[0];
};

/* Used for MT_INSN. */
struct InsnEntry {
   union Tlv tlv;
   Addr pc;
   UChar value[0];
};

/* Used for MT_INSN_EXEC. */
struct InsnExecEntry {
   union Tlv tlv;
   Addr pc;
};

/* Used for MT_GET_REG_NX and MT_PUT_REG_NX. */
struct LdStNxEntry {
   union Tlv tlv;
   Addr pc;
   Addr addr;
   UIntPtr size;
};

/* Used for MT_MMAP. */
struct MmapEntry {
   union Tlv tlv;
   Addr start;
   Addr end;
   UIntPtr flags;
   UChar value[0];
};

static void open_trace_file(void)
{
   struct HeaderEntry* entry;
   SysRes o;

   o = VG_(open)(trace_file_name,
                 VKI_O_CREAT | VKI_O_TRUNC | VKI_O_RDWR,
                 0644);
   if (sr_isError(o)) {
      VG_(umsg)("error: can't open '%s'\n", trace_file_name);
      VG_(exit)(1);
   }
   trace_fd = VG_(safe_fd)(sr_Res(o));
   if (trace_fd == -1) {
      VG_(umsg)("error: safe_fd for '%s' failed\n", trace_file_name);
      VG_(exit)(1);
   }
   trace_start = VG_(malloc)("mt.trace", TRACE_BUFFER_SIZE);
   trace = trace_start;
   trace_end = trace_start + TRACE_BUFFER_SIZE;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct HeaderEntry) == 8 :
                    VG_WORDSIZE == 8 ? sizeof(struct HeaderEntry) == 16 :
                    0);
   entry = (struct HeaderEntry*)trace;
   entry->tlv.tag = MT_MAGIC;
   entry->tlv.length = sizeof(struct HeaderEntry);
   entry->e_machine = VG_ELF_MACHINE;
   trace += sizeof(struct HeaderEntry);
}

static void flush_trace_buffer(void)
{
   Int traceSize = trace - trace_start;

   VG_(write)(trace_fd, trace_start, traceSize);
   VG_(memset)(trace_start, 0, traceSize);
   trace = trace_start;
}

static void close_trace_file(void)
{
   flush_trace_buffer();
   VG_(free)(trace_start);
   VG_(close)(trace_fd);
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
                                           mkPtr(trace_end - MAX_ENTRY_LENGTH),
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
                           Addr pc,
                           IRExpr* addr,
                           UShort tag,
                           IRExpr* value)
{
   IRTemp currentEntryPtr;
   Int valueLength;
   Int entryLength;
   union Tlv tlv;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct LdStEntry) == 12 :
                    VG_WORDSIZE == 8 ? sizeof(struct LdStEntry) == 24 :
                    0);
   valueLength = sizeofIRType(typeOfIRExpr(out->tyenv, value));
   entryLength = sizeof(struct LdStEntry) + valueLength;
   /* entry = ...; */
   currentEntryPtr = load_current_entry_ptr(out);
   /* entry->tlv = tlv; */
   tlv.packed = 0;
   tlv.tag = tag;
   tlv.length = entryLength;
   store_value(out,
               currentEntryPtr,
               offsetof(struct LdStEntry, tlv.packed),
               mkUIntPtr(tlv.packed));
   /* entry->pc = pc; */
   store_value(out,
               currentEntryPtr,
               offsetof(struct LdStEntry, pc),
               mkUIntPtr(pc));
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

static void add_reg_entry(IRSB* out, Addr pc, Int offset)
{
   add_ldst_entry(out,
                  pc,
                  mkUIntPtr(offset),
                  MT_REG,
                  IRExpr_Get(offset, Ity_Ptr));
}

static void add_reg_entries(IRSB* out, Addr pc)
{
   Int i;

   for (i = 0; i < sizeof(VexGuestArchState); i += VG_WORDSIZE)
      add_reg_entry(out, pc, i);
}

static void add_insn_entry(Addr pc, UInt insn_length)
{
   struct InsnEntry* entry;
   Int alignedEntryLength;
   Int entryLength;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct InsnEntry) == 8 :
                    VG_WORDSIZE == 8 ? sizeof(struct InsnEntry) == 16 :
                    0);
   entryLength = sizeof(struct InsnEntry) + insn_length;
   entry = (struct InsnEntry*)trace;
   entry->tlv.tag = MT_INSN;
   entry->tlv.length = entryLength;
   entry->pc = pc;
   VG_(memcpy)(entry->value, (void*)pc, insn_length);
   alignedEntryLength = ALIGN_UP(entryLength, sizeof(UIntPtr));
   tl_assert(alignedEntryLength <= MAX_ENTRY_LENGTH);
   trace += alignedEntryLength;
   if (trace > trace_end - MAX_ENTRY_LENGTH)
      flush_trace_buffer();
}

static void add_insn_exec_entry(IRSB* out, Addr pc)
{
   IRTemp currentEntryPtr;
   Int entryLength;
   union Tlv tlv;

   MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct InsnExecEntry) == 8 :
                    VG_WORDSIZE == 8 ? sizeof(struct InsnExecEntry) == 16 :
                    0);
   currentEntryPtr = load_current_entry_ptr(out);
   entryLength = sizeof(struct InsnExecEntry);
   tlv.packed = 0;
   tlv.tag = MT_INSN_EXEC;
   tlv.length = entryLength;
   store_value(out,
               currentEntryPtr,
               offsetof(struct InsnExecEntry, tlv.packed),
               mkUIntPtr(tlv.packed));
   store_value(out,
               currentEntryPtr,
               offsetof(struct InsnExecEntry, pc),
               mkUIntPtr(pc));
   update_current_entry_ptr(out, currentEntryPtr, entryLength);
}

static void add_raw_entries(XArray* entries)
{
   void* ptr;
   Word n;

   VG_(getContentsXA_UNSAFE)(entries, &ptr, &n);
   if (trace + n + MAX_ENTRY_LENGTH > trace_end)
      flush_trace_buffer();
   VG_(memcpy)(trace, ptr, n);
   trace += n;
}

static void trace_segments(void)
{
   Addr* segStarts;
   Int nSegStarts;
   Int i;

   segStarts = VG_(get_segment_starts)(SkFileC | SkAnonC | SkShmC,
                                       &nSegStarts);
   for (i = 0; i < nSegStarts; i++) {
      struct MmapEntry* entry;
      Int alignedEntryLength;
      const NSegment* seg;
      const HChar* name;
      Int entryLength;
      Int nameLength;

      seg = VG_(am_find_nsegment)(segStarts[i]);
      name = VG_(am_get_filename)(seg);
      nameLength = name == NULL ? 1 : VG_(strlen)(name) + 1;
      entryLength = sizeof(struct MmapEntry) + nameLength;
      alignedEntryLength = ALIGN_UP(entryLength, sizeof(UIntPtr));
      tl_assert(alignedEntryLength <= MAX_ENTRY_LENGTH);
      entry = (struct MmapEntry*)trace;
      entry->tlv.tag = MT_MMAP;
      entry->tlv.length = entryLength;
      entry->start = seg->start;
      entry->end = seg->end;
      entry->flags = (seg->hasR ? 1 : 0) |
                     (seg->hasW ? 2 : 0) |
                     (seg->hasX ? 4 : 0);
      if (nameLength == 1)
         entry->value[0] = 0;
      else
         VG_(memcpy)(entry->value, name, nameLength);
      trace += alignedEntryLength;
      if (trace > trace_end - MAX_ENTRY_LENGTH)
         flush_trace_buffer();
   }
}

static Int get_pc_flags(Addr pc)
{
   Int flags = 0;
   UInt i;

   for (i = 0; i < n_pc_ranges; i++)
      if (pc >= pc_ranges[i].start && pc <= pc_ranges[i].end)
         flags |= pc_ranges[i].flags;
   return flags;
}

static void show_pc_ranges(void)
{
   UInt i;

   VG_(umsg)("Traced addresses:\n");
   for (i = 0; i < n_pc_ranges; i++)
      VG_(umsg)("%016llx-%016llx %c%c%c%c\n",
                (ULong)pc_ranges[i].start,
                (ULong)pc_ranges[i].end,
                (pc_ranges[i].flags & AR_MEM) ? 'm' : '-',
                (pc_ranges[i].flags & AR_REGS) ? 'r' : '-',
                (pc_ranges[i].flags & AR_INSNS) ? 'i' : '-',
                (pc_ranges[i].flags & AR_ALL_REGS) ? 'R' : '-');
}

static Bool add_pc_range(const HChar* spec)
{
   const HChar* colon;
   const HChar* dash;
   HChar* endptr;

   if (n_pc_ranges == MAX_PC_RANGES)
      return False;
   dash = VG_(strchr)(spec, '-');
   if (dash == NULL)
      return False;
   colon = VG_(strchr)(dash, ':');
   pc_ranges[n_pc_ranges].start = VG_(strtoull16)(spec, &endptr);
   if (endptr != dash)
      return False;
   pc_ranges[n_pc_ranges].end = VG_(strtoull16)(dash + 1, &endptr);
   if (colon == NULL) {
      if (*endptr != '\0')
         return False;
      pc_ranges[n_pc_ranges].flags = AR_DEFAULT;
   } else {
      if (endptr != colon)
         return False;
      for (endptr++; *endptr; endptr++) {
         switch (*endptr) {
         case 'i':
            pc_ranges[n_pc_ranges].flags |= AR_INSNS;
            break;
         case 'm':
            pc_ranges[n_pc_ranges].flags |= AR_MEM;
            break;
         case 'r':
            pc_ranges[n_pc_ranges].flags |= AR_REGS;
            break;
         case 'R':
            pc_ranges[n_pc_ranges].flags |= AR_ALL_REGS;
            break;
         default:
            return False;
         }
      }
   }
   n_pc_ranges++;
   return True;
}

static Bool mt_process_cmd_line_option(const HChar* arg)
{
   const HChar* tmpStr;

   if (VG_STR_CLO(arg, "--pc-range", tmpStr))
      return add_pc_range(tmpStr);
   else
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
   if (n_pc_ranges == 0) {
      pc_ranges[0].start = 0;
      pc_ranges[0].end = (Addr)-1;
      pc_ranges[0].flags = AR_DEFAULT;
      n_pc_ranges = 1;
   }

   show_pc_ranges();
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
   Int pcFlags = 0;
   Addr pc = 0;
   IRSB* out;
   Int i;

   out = deepCopyIRSBExceptStmts(bb);
   for (i = 0; i < bb->stmts_used; i++) {
      IRStmt* stmt = bb->stmts[i];

      switch (stmt->tag) {
      case Ist_NoOp:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_IMark:
         pc = stmt->Ist.IMark.addr;
         pcFlags = get_pc_flags(pc);
         if (pcFlags)
            add_insn_entry(pc, stmt->Ist.IMark.len);
         if (pcFlags & AR_INSNS)
            add_insn_exec_entry(out, pc);
         if (pcFlags & AR_ALL_REGS)
            add_reg_entries(out, pc);
         addStmtToIRSB(out, stmt);
         break;
      case Ist_AbiHint:
         addStmtToIRSB(out, stmt);
         break;
      case Ist_Put:
         if (pcFlags & AR_REGS) {
            IRExpr* addr = mkUIntPtr(stmt->Ist.Put.offset);
            IRExpr* data = stmt->Ist.Put.data;

            add_ldst_entry(out, pc, addr, MT_PUT_REG, data);
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

            add_ldst_entry(out, pc, addr, MT_LOAD, data);
         } else if ((pcFlags & AR_REGS) && data->tag == Iex_Get) {
            IRExpr* addr = mkUIntPtr(data->Iex.Get.offset);

            add_ldst_entry(out, pc, addr, MT_GET_REG, data);
         }
         addStmtToIRSB(out, stmt);
         break;
      }
      case Ist_Store:
         if (pcFlags & AR_MEM) {
            IRExpr* addr = stmt->Ist.Store.addr;
            IRExpr* data = stmt->Ist.Store.data;

            add_ldst_entry(out, pc, addr, MT_STORE, data);
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
         Int pcFlagsNx = pcFlags;
         XArray* entries;
         Addr pcNx = pc;
         IRDirty* d;
         Int j;

         MT_STATIC_ASSERT(VG_WORDSIZE == 4 ? sizeof(struct LdStNxEntry) == 16 :
                          VG_WORDSIZE == 8 ? sizeof(struct LdStNxEntry) == 32 :
                          0);
         entries = VG_(newXA)(VG_(malloc),
                              "mt.nx.1",
                              VG_(free),
                              sizeof(UChar));
         for (j = i + 1; j < bb->stmts_used; j++) {
            IRStmt* stmtNx = bb->stmts[j];

            switch (stmtNx->tag) {
            case Ist_IMark:
               pcNx = stmtNx->Ist.IMark.addr;
               pcFlagsNx = get_pc_flags(pcNx);
               break;
            case Ist_Put:
               if (pcFlagsNx & AR_REGS) {
                  IRExpr* data = stmtNx->Ist.Put.data;

                  entry.tlv.packed = 0;
                  entry.tlv.tag = MT_PUT_REG_NX;
                  entry.tlv.length = sizeof entry;
                  entry.pc = pcNx;
                  entry.addr = stmtNx->Ist.Put.offset;
                  entry.size = sizeofIRType(typeOfIRExpr(out->tyenv, data));
                  VG_(addBytesToXA)(entries, &entry, sizeof entry);
               }
               break;
            case Ist_WrTmp: {
               IRExpr* data = stmtNx->Ist.WrTmp.data;

               if ((pcFlagsNx & AR_REGS) && data->tag == Iex_Get) {
                  entry.tlv.packed = 0;
                  entry.tlv.tag = MT_GET_REG_NX;
                  entry.tlv.length = sizeof entry;
                  entry.pc = pcNx;
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
                               "add_raw_entries",
                               add_raw_entries,
                               mkIRExprVec_1(mkPtr(entries)));
         d->guard = stmt->Ist.Exit.guard;
         d->mFx   = Ifx_Write;
         d->mAddr = mkPtr(&trace);
         d->mSize = sizeof trace;
         addStmtToIRSB(out, IRStmt_Dirty(d));

         addStmtToIRSB(out, stmt);
         break;
      }
      default:
         ppIRStmt(stmt);
         tl_assert(0);
      }
   }
   return out;
}

static void mt_fini(Int exitcode)
{
   trace_segments();
   close_trace_file();
}

static void mt_pre_clo_init(void)
{
   VG_(details_name)("Memory Tracer");
   VG_(details_description)("Valgrind tool for tracing memory accesses");
   VG_(details_copyright_author)(
      "Copyright (C) 2019-2020, and GNU GPL'd, by mephi42.");
   VG_(details_bug_reports_to)("https://github.com/mephi42/memtrace");
   VG_(basic_tool_funcs)(mt_post_clo_init,
                         mt_instrument,
                         mt_fini);
   VG_(needs_command_line_options)(mt_process_cmd_line_option,
                                   mt_print_usage,
                                   mt_print_debug_usage);
   /* Valgrind passes an optimized IRSB to mt_instrument, in which nearby
      instructions might be intertwined. Therefore, in order to get the
      accurate associaton of data accesses to instructions, we need to look at
      one instruction at a time. */
   VG_(clo_vex_control).guest_max_insns = 1;
   open_trace_file();
}

VG_DETERMINE_INTERFACE_VERSION(mt_pre_clo_init)
