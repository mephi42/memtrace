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
#define Iop_CmpEQPtr Iop_CmpEQ64
#define MT_MAGIC 0x4d543634
#elif VG_WORDSIZE == 4
typedef UInt UIntPtr;
#define Ity_Ptr Ity_I32
#define Iop_AddPtr Iop_Add32
#define IRConst_UIntPtr IRConst_U32
#define Iop_CmpEQPtr Iop_CmpEQ32
#define MT_MAGIC 0x4d543332
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

#define MT_LOAD (1 << 0)
#define MT_STORE (1 << 1)
#define MT_REG (1 << 2)
#define MT_INSN (1 << 3)
#define MT_GET_REG (1 << 4)
#define MT_PUT_REG (1 << 5)
#define MT_INSN_EXEC (1 << 6)
#define MT_GET_REG_NX (1 << 7)
#define MT_PUT_REG_NX (1 << 8)
#define MT_SIZE_SHIFT 16

typedef struct {
   union {
      struct {
         UIntPtr pc;
         UIntPtr addr;
         /* combination of MT_* flags */
         UIntPtr flags;
      };
      struct {
         UInt magic;
         UShort e_machine;
      } header;
      UChar pad[32];
   };
   /* max sizeofIRType() is 32 at the moment */
   UChar value[32];
} MTEntry;
#define MAX_VALUE_SIZE sizeof(((MTEntry*)0)->value)

#define TRACE_BUFFER_SIZE (1024 * 1024 * 1024)
static const HChar trace_file_name[] = "memtrace.out";
static Int trace_fd;
static MTEntry* trace_start;
static MTEntry* trace;
static MTEntry* trace_end;
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

static void open_trace_file(void)
{
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
   trace_end = trace_start + TRACE_BUFFER_SIZE / sizeof(MTEntry);

   /* this is always the first entry */
   trace->header.magic = MT_MAGIC;
   trace->header.e_machine = VG_ELF_MACHINE;
   trace++;
}

static void flush_trace_buffer(void)
{
   Int traceSize = (trace - trace_start) * sizeof(MTEntry);

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

static void store_pc(IRSB* out, IRTemp currentEntryPtr, IRExpr* pc)
{
   IRTemp pcPtr;
   IRExpr* calculatePcPtr;

   /* pcPtr = &currentEntryPtr->pc; */
   pcPtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculatePcPtr = IRExpr_Binop(Iop_AddPtr,
                                 IRExpr_RdTmp(currentEntryPtr),
                                 mkUIntPtr(offsetof(MTEntry, pc)));
   addStmtToIRSB(out, IRStmt_WrTmp(pcPtr, calculatePcPtr));
   /* (*pcPtr) = pc; */
   addStmtToIRSB(out, IRStmt_Store(END, IRExpr_RdTmp(pcPtr), pc));
}

static void store_addr(IRSB* out, IRTemp currentEntryPtr, IRExpr* addr)
{
   IRTemp addrPtr;
   IRExpr* calculateAddrPtr;

   /* addrPtr = &currentEntryPtr->addr; */
   addrPtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculateAddrPtr = IRExpr_Binop(Iop_AddPtr,
                                   IRExpr_RdTmp(currentEntryPtr),
                                   mkUIntPtr(offsetof(MTEntry, addr)));
   addStmtToIRSB(out, IRStmt_WrTmp(addrPtr, calculateAddrPtr));
   /* (*addrPtr) = addr; */
   addStmtToIRSB(out, IRStmt_Store(END, IRExpr_RdTmp(addrPtr), addr));
}

static void store_flags(IRSB* out, IRTemp currentEntryPtr, IRExpr* flags)
{
   IRTemp flagsPtr;
   IRExpr* calculateFlagsPtr;

   /* flagsPtr = &currentEntryPtr->flags; */
   flagsPtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculateFlagsPtr = IRExpr_Binop(Iop_AddPtr,
                                    IRExpr_RdTmp(currentEntryPtr),
                                    mkUIntPtr(offsetof(MTEntry, flags)));
   addStmtToIRSB(out, IRStmt_WrTmp(flagsPtr, calculateFlagsPtr));
   /* (*flagsPtr) = flags; */
   addStmtToIRSB(out, IRStmt_Store(END, IRExpr_RdTmp(flagsPtr), flags));
}

static void store_value(IRSB* out, IRTemp currentEntryPtr, IRExpr* value)
{
   IRTemp valuePtr;
   IRExpr* calculateValuePtr;
   IRTemp valueTmp;

   /* valuePtr = &currentEntryPtr->value; */
   valuePtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculateValuePtr = IRExpr_Binop(Iop_AddPtr,
                                    IRExpr_RdTmp(currentEntryPtr),
                                    mkUIntPtr(offsetof(MTEntry, value)));
   addStmtToIRSB(out, IRStmt_WrTmp(valuePtr, calculateValuePtr));
   /* (*(typeof(value)*)valuePtr) = value; */
   valueTmp = newIRTemp(out->tyenv, typeOfIRExpr(out->tyenv, value));
   addStmtToIRSB(out, IRStmt_WrTmp(valueTmp, value));
   addStmtToIRSB(out, IRStmt_Store(END,
                                   IRExpr_RdTmp(valuePtr),
                                   IRExpr_RdTmp(valueTmp)));
}

static void update_current_entry_ptr(IRSB* out,
                                     IRTemp currentEntryPtr)
{
   IRTemp updatedEntryPtr, isFlushNeeded;
   IRExpr* incEntryPtr;
   IRDirty* d;

   /* updatedEntryPtr = currentEntryPtr + 1; */
   updatedEntryPtr = newIRTemp(out->tyenv, Ity_Ptr);
   incEntryPtr = IRExpr_Binop(Iop_AddPtr,
                              IRExpr_RdTmp(currentEntryPtr),
                              mkUIntPtr(sizeof(MTEntry)));
   addStmtToIRSB(out, IRStmt_WrTmp(updatedEntryPtr, incEntryPtr));
   /* trace = updatedEntryPtr; */
   addStmtToIRSB(out, IRStmt_Store(END,
                                   mkPtr(&trace),
                                   IRExpr_RdTmp(updatedEntryPtr)));
   /* isFlushNeeded = updatedEntryPtr == traceEnd; */
   isFlushNeeded = newIRTemp(out->tyenv, Ity_I1);
   addStmtToIRSB(out,
                 IRStmt_WrTmp(isFlushNeeded,
                              IRExpr_Binop(Iop_CmpEQPtr,
                                           IRExpr_RdTmp(updatedEntryPtr),
                                           mkPtr(trace_end))));
   /* if (isFlushNeeded) flush_trace_buffer(); */
   d = unsafeIRDirty_0_N(0,
                         "flush_trace_buffer",
                         flush_trace_buffer,
                         mkIRExprVec_0());
   d->guard = IRExpr_RdTmp(isFlushNeeded);
   d->mFx   = Ifx_Write;
   d->mAddr = mkPtr(&trace);
   d->mSize = sizeof(trace);
   addStmtToIRSB(out, IRStmt_Dirty(d));
}

static void add_ldst_entry(IRSB* out,
                           Addr pc,
                           IRExpr* addr,
                           UIntPtr flags,
                           IRExpr* value)
{
   IRTemp currentEntryPtr;
   Int valueSize;

   currentEntryPtr = load_current_entry_ptr(out);
   store_pc(out, currentEntryPtr, mkUIntPtr(pc));
   store_addr(out, currentEntryPtr, addr);
   valueSize = sizeofIRType(typeOfIRExpr(out->tyenv, value));
   tl_assert(valueSize <= MAX_VALUE_SIZE);
   store_flags(out,
               currentEntryPtr,
               mkUIntPtr(valueSize << MT_SIZE_SHIFT | flags));
   store_value(out, currentEntryPtr, value);
   update_current_entry_ptr(out, currentEntryPtr);
}

static void add_reg_entry(IRSB* out, Addr pc, Int offset)
{
   IRTemp currentEntryPtr;
   UIntPtr flags;

   currentEntryPtr = load_current_entry_ptr(out);
   store_pc(out, currentEntryPtr, mkUIntPtr(pc));
   store_addr(out, currentEntryPtr, mkUIntPtr(offset));
   flags = VG_WORDSIZE << MT_SIZE_SHIFT | MT_REG;
   store_flags(out, currentEntryPtr, mkUIntPtr(flags));
   store_value(out, currentEntryPtr, IRExpr_Get(offset, Ity_Ptr));
   update_current_entry_ptr(out, currentEntryPtr);
}

static void add_reg_entries(IRSB* out, Addr pc)
{
   Int i;

   for (i = 0; i < sizeof(VexGuestArchState); i += VG_WORDSIZE)
      add_reg_entry(out, pc, i);
}

static void add_insn_entry(Addr pc, UInt len)
{
   if (trace + 1 >= trace_end)
      flush_trace_buffer();
   trace->pc = pc;
   trace->flags = len << MT_SIZE_SHIFT | MT_INSN;
   VG_(memcpy)(trace->value, (void*)pc, len);
   trace++;
}

static void add_insn_exec_entry(IRSB* out, Addr pc)
{
   IRTemp currentEntryPtr;

   currentEntryPtr = load_current_entry_ptr(out);
   store_pc(out, currentEntryPtr, mkUIntPtr(pc));
   store_flags(out, currentEntryPtr, mkUIntPtr(MT_INSN_EXEC));
   update_current_entry_ptr(out, currentEntryPtr);
}

static void add_raw_entries(XArray* entries)
{
   void* ptr;
   Word n;

   VG_(getContentsXA_UNSAFE)(entries, &ptr, &n);
   if (trace + n >= trace_end)
      flush_trace_buffer();
   VG_(memcpy)(trace, ptr, sizeof(MTEntry) * n);
   trace += n;
}

static void show_segments(void)
{
   Addr* segStarts;
   Int nSegStarts;
   Int i;

   VG_(umsg)("Segments:\n");
   segStarts = VG_(get_segment_starts)(SkFileC | SkAnonC | SkShmC,
                                       &nSegStarts);
   for (i = 0; i < nSegStarts; i++) {
      const NSegment* seg;

      seg = VG_(am_find_nsegment)(segStarts[i]);
      VG_(umsg)("%016llx-%016llx %c%c%c %s\n",
                (ULong)seg->start,
                (ULong)seg->end + 1,
                seg->hasR ? 'r' : '-',
                seg->hasW ? 'w' : '-',
                seg->hasX ? 'x' : '-',
                VG_(am_get_filename)(seg));
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
         Int pcFlagsNx = pcFlags;
         XArray* entries;
         Addr pcNx = pc;
         MTEntry entry;
         IRDirty* d;
         Int j;

         entries = VG_(newXA)(VG_(malloc),
                              "mt.nx.1",
                              VG_(free),
                              sizeof(MTEntry));
         VG_(memset)(&entry, 0, sizeof(entry));
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
                  Int size;

                  size = sizeofIRType(typeOfIRExpr(out->tyenv, data));
                  entry.pc = pcNx;
                  entry.addr = stmtNx->Ist.Put.offset;
                  entry.flags = size << MT_SIZE_SHIFT | MT_PUT_REG_NX;
                  VG_(addToXA)(entries, &entry);
               }
               break;
            case Ist_WrTmp: {
               IRExpr* data = stmtNx->Ist.WrTmp.data;

               if ((pcFlagsNx & AR_REGS) && data->tag == Iex_Get) {
                  Int size = sizeofIRType(typeOfIRExpr(out->tyenv, data));

                  entry.pc = pcNx;
                  entry.addr = data->Iex.Get.offset;
                  entry.flags = size << MT_SIZE_SHIFT | MT_GET_REG_NX;
                  VG_(addToXA)(entries, &entry);
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
         d->mSize = sizeof(trace);
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
   close_trace_file();
   show_segments();
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
