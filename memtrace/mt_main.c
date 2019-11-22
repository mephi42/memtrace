#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_tooliface.h"

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

static inline IRExpr* mkUIntPtr(UIntPtr val)
{
   return IRExpr_Const(IRConst_UIntPtr(val));
}

static inline IRExpr* mkPtr(void* ptr)
{
   return mkUIntPtr((UIntPtr)ptr);
}

static ULong count;
#define Ity_Count Ity_I64

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
   IRSB* out;
   int i;

   out = deepCopyIRSBExceptStmts(bb);
   for (i = 0; i < bb->stmts_used; i++) {
      switch (bb->stmts[i]->tag) {
      case Ist_NoOp:
         addStmtToIRSB(out, bb->stmts[i]);
         break;
      case Ist_IMark: {
         IRTemp currentCount;
         IRExpr* loadCount;
         IRTemp updatedCount;
         IRExpr* incCount;
         addStmtToIRSB(out, bb->stmts[i]);
         currentCount = newIRTemp(out->tyenv, Ity_Count);
         loadCount = IRExpr_Load(END, Ity_Count, mkPtr(&count));
         addStmtToIRSB(out, IRStmt_WrTmp(currentCount, loadCount));
         updatedCount = newIRTemp(out->tyenv, Ity_Count);
         incCount = IRExpr_Binop(Iop_AddPtr,
                                 IRExpr_RdTmp(currentCount),
                                 mkUIntPtr(1));
         addStmtToIRSB(out, IRStmt_WrTmp(updatedCount, incCount));
         addStmtToIRSB(out, IRStmt_Store(END,
                                         mkPtr(&count),
                                         IRExpr_RdTmp(updatedCount)));
         break;
      }
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
   VG_(printf)("count = %llu\n", count);
}

static void mt_pre_clo_init(void)
{
   VG_(details_name)("Memory Tracer");
   VG_(details_description)("Valgrind tool for tracing memory accesses");
   VG_(details_copyright_author)(
      "Copyright (C) 2019, and GNU GPL'd, by mephi42.");
   VG_(details_bug_reports_to)("https://github.com/mephi42/memtrace");
   VG_(basic_tool_funcs)(mt_post_clo_init,
                         mt_instrument,
                         mt_fini);
}

VG_DETERMINE_INTERFACE_VERSION(mt_pre_clo_init)
