#include "pub_core_aspacemgr.h"
#include "pub_core_libcfile.h"
#include "pub_core_syscall.h"
#include "pub_tool_aspacehl.h"
#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_options.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"

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
#elif VG_WORDSIZE == 4
typedef UInt UIntPtr;
#define Ity_Ptr Ity_I32
#define Iop_AddPtr Iop_Add32
#define IRConst_UIntPtr IRConst_U32
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

typedef struct {
   UIntPtr pc;
   UIntPtr addr;
} MTEntry;

#define MAX_TRACE_SIZE (1024 * 1024 * 1024)
static const char trace_file_name[] = "memtrace.out";
static int trace_fd;
static MTEntry* trace_start;
static MTEntry* trace;
static Addr pc_start = 0;
static Addr pc_end = (Addr)-1;

static void add_entry(IRSB* out, Addr pc, IRExpr* addr)
{
   IRTemp currentEntryPtr;
   IRExpr* loadEntryPtr;
   IRTemp pcPtr;
   IRExpr* calculatePcPtr;
   IRTemp addrPtr;
   IRExpr *calculateAddrPtr;
   IRTemp updatedEntryPtr;
   IRExpr* incEntryPtr;
   /* currentEntryPtr = trace; */
   currentEntryPtr = newIRTemp(out->tyenv, Ity_Ptr);
   loadEntryPtr = IRExpr_Load(END, Ity_Ptr, mkPtr(&trace));
   addStmtToIRSB(out, IRStmt_WrTmp(currentEntryPtr, loadEntryPtr));
   /* pcPtr = &currentEntryPtr->pc; */
   pcPtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculatePcPtr = IRExpr_Binop(Iop_AddPtr,
                                 IRExpr_RdTmp(currentEntryPtr),
                                 mkUIntPtr(offsetof(MTEntry, pc)));
   addStmtToIRSB(out, IRStmt_WrTmp(pcPtr, calculatePcPtr));
   /* (*pcPtr) = pc; */
   addStmtToIRSB(out, IRStmt_Store(END,
                                   IRExpr_RdTmp(pcPtr),
                                   mkUIntPtr(pc)));
   /* addrPtr = &currentEntryPtr->addr; */
   addrPtr = newIRTemp(out->tyenv, Ity_Ptr);
   calculateAddrPtr = IRExpr_Binop(Iop_AddPtr,
                                   IRExpr_RdTmp(currentEntryPtr),
                                   mkUIntPtr(offsetof(MTEntry, addr)));
   addStmtToIRSB(out, IRStmt_WrTmp(addrPtr, calculateAddrPtr));
   /* (*addrPtr) = addr; */
   addStmtToIRSB(out, IRStmt_Store(END,
                                   IRExpr_RdTmp(addrPtr),
                                   addr));
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
}

static void show_segments(void)
{
   Int n_seg_starts;
   Addr* seg_starts;
   Int i;

   VG_(umsg)("Segments:\n");
   seg_starts = VG_(get_segment_starts)(SkFileC | SkAnonC | SkShmC,
                                        &n_seg_starts);
   for (i = 0; i < n_seg_starts; i++) {
      const NSegment* seg;

      seg = VG_(am_find_nsegment)(seg_starts[i]);
      VG_(umsg)("%016llx-%016llx %s\n",
                (ULong)seg->start,
                (ULong)seg->end + 1,
                VG_(am_get_filename)(seg));
   }
}

static Bool is_pc_interesting(Addr pc)
{
   return pc >= pc_start && pc <= pc_end;
}

static Bool mt_process_cmd_line_option(const HChar* arg)
{
   if (VG_BHEX_CLO(arg, "--pc-start", pc_start, 0, (Addr)-1))
      return True;
   else if (VG_BHEX_CLO(arg, "--pc-end", pc_end, 0, (Addr)-1))
      return True;
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
   Addr pc = 0;
   IRSB* out;
   int i;

   out = deepCopyIRSBExceptStmts(bb);
   for (i = 0; i < bb->stmts_used; i++) {
      switch (bb->stmts[i]->tag) {
      case Ist_NoOp:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_IMark:
         pc = bb->stmts[i]->Ist.IMark.addr;
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_AbiHint:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_Put:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_PutI:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_WrTmp:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_Store:
         if (is_pc_interesting(pc))
            add_entry(out, pc, bb->stmts[i]->Ist.Store.addr);
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_LoadG:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_StoreG:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_CAS:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_LLSC:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_Dirty:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_MBE:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_Exit:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      default:
         tl_assert(0);
      }
   }
   return out;
}

static void mt_fini(Int exitcode)
{
   ULong trace_size;
   SysRes o;
   VG_(am_munmap_valgrind)((Addr)trace_start, MAX_TRACE_SIZE);
   trace_size = (char*)trace - (char*)trace_start;
   o = VG_(do_syscall2)(__NR_ftruncate, trace_fd, trace_size);
   if (sr_isError(o)) {
      VG_(umsg)("error: can't truncate '%s'\n", trace_file_name);
      VG_(exit)(1);
   }
   VG_(close)(trace_fd);
   show_segments();
}

static void mt_pre_clo_init(void)
{
   SysRes o;
   VG_(details_name)("Memory Tracer");
   VG_(details_description)("Valgrind tool for tracing memory accesses");
   VG_(details_copyright_author)(
      "Copyright (C) 2019, and GNU GPL'd, by mephi42.");
   VG_(details_bug_reports_to)("https://github.com/mephi42/memtrace");
   VG_(basic_tool_funcs)(mt_post_clo_init,
                         mt_instrument,
                         mt_fini);
   VG_(needs_command_line_options)(mt_process_cmd_line_option,
                                   mt_print_usage,
                                   mt_print_debug_usage);
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
   o = VG_(do_syscall2)(__NR_ftruncate, trace_fd, MAX_TRACE_SIZE);
   if (sr_isError(o)) {
      VG_(umsg)("error: can't reserve space for '%s'\n", trace_file_name);
      VG_(exit)(1);
   }
   o = VG_(am_shared_mmap_file_float_valgrind)(MAX_TRACE_SIZE,
                                               VKI_PROT_READ | VKI_PROT_WRITE,
                                               trace_fd,
                                               0);
   if (sr_isError(o)) {
      VG_(umsg)("error: can't mmap '%s'\n", trace_file_name);
      VG_(exit)(1);
   }
   trace_start = (MTEntry*)sr_Res(o);
   trace = trace_start;
}

VG_DETERMINE_INTERFACE_VERSION(mt_pre_clo_init)
