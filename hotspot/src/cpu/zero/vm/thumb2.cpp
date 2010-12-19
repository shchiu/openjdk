/*
 * Copyright 2009, 2010 Edward Nevill
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#undef THUMB2EE
#if !defined(DISABLE_THUMB2) && defined(HOTSPOT_ASM) && !defined(SHARK)
#define THUMB2EE
#endif

#ifdef THUMB2EE

#define T2EE_PRINT_COMPILATION
#define T2EE_PRINT_STATISTICS
//#define T2EE_PRINT_DISASS
#define T2EE_PRINT_REGUSAGE

#ifdef T2EE_PRINT_COMPILATION
static char *t2ee_print_compilation;
#endif

#ifdef T2EE_PRINT_STATISTICS
static char *t2ee_print_statistics;
#endif

#ifdef T2EE_PRINT_DISASS
static char *t2ee_print_disass;
#endif

#ifdef T2EE_PRINT_REGUSAGE
static char *t2ee_print_regusage;
#endif

#define THUMB2_CODEBUF_SIZE (8 * 1024 * 1024)
#define THUMB2_MAX_BYTECODE_SIZE 10000
#define THUMB2_MAX_T2CODE_SIZE 65000
#define THUMB2_MAXLOCALS 1000

#include <sys/mman.h>

#include "incls/_precompiled.incl"

#ifdef T2EE_PRINT_DISASS
#include "dis-asm.h"
#include "bfd.h"
#endif

#define opc_nop			0x00
#define opc_aconst_null		0x01
#define opc_iconst_m1		0x02
#define opc_iconst_0		0x03
#define opc_iconst_1		0x04
#define opc_iconst_2		0x05
#define opc_iconst_3		0x06
#define opc_iconst_4		0x07
#define opc_iconst_5		0x08
#define opc_lconst_0		0x09
#define opc_lconst_1		0x0a
#define opc_fconst_0		0x0b
#define opc_fconst_1		0x0c
#define opc_fconst_2		0x0d
#define opc_dconst_0		0x0e
#define opc_dconst_1		0x0f
#define opc_bipush		0x10
#define opc_sipush		0x11
#define opc_ldc			0x12
#define opc_ldc_w		0x13
#define opc_ldc2_w		0x14
#define opc_iload		0x15
#define opc_lload		0x16
#define opc_fload		0x17
#define opc_dload		0x18
#define opc_aload		0x19
#define opc_iload_0		0x1a
#define opc_iload_1		0x1b
#define opc_iload_2		0x1c
#define opc_iload_3		0x1d
#define opc_lload_0		0x1e
#define opc_lload_1		0x1f
#define opc_lload_2		0x20
#define opc_lload_3		0x21
#define opc_fload_0		0x22
#define opc_fload_1		0x23
#define opc_fload_2		0x24
#define opc_fload_3		0x25
#define opc_dload_0		0x26
#define opc_dload_1		0x27
#define opc_dload_2		0x28
#define opc_dload_3		0x29
#define opc_aload_0		0x2a
#define opc_aload_1		0x2b
#define opc_aload_2		0x2c
#define opc_aload_3		0x2d
#define opc_iaload		0x2e
#define opc_laload		0x2f
#define opc_faload		0x30
#define opc_daload		0x31
#define opc_aaload		0x32
#define opc_baload		0x33
#define opc_caload		0x34
#define opc_saload		0x35
#define opc_istore		0x36
#define opc_lstore		0x37
#define opc_fstore		0x38
#define opc_dstore		0x39
#define opc_astore		0x3a
#define opc_istore_0		0x3b
#define opc_istore_1		0x3c
#define opc_istore_2		0x3d
#define opc_istore_3		0x3e
#define opc_lstore_0		0x3f
#define opc_lstore_1		0x40
#define opc_lstore_2		0x41
#define opc_lstore_3		0x42
#define opc_fstore_0		0x43
#define opc_fstore_1		0x44
#define opc_fstore_2		0x45
#define opc_fstore_3		0x46
#define opc_dstore_0		0x47
#define opc_dstore_1		0x48
#define opc_dstore_2		0x49
#define opc_dstore_3		0x4a
#define opc_astore_0		0x4b
#define opc_astore_1		0x4c
#define opc_astore_2		0x4d
#define opc_astore_3		0x4e
#define opc_iastore		0x4f
#define opc_lastore		0x50
#define opc_fastore		0x51
#define opc_dastore		0x52
#define opc_aastore		0x53
#define opc_bastore		0x54
#define opc_castore		0x55
#define opc_sastore		0x56
#define opc_pop			0x57
#define opc_pop2		0x58
#define opc_dup			0x59
#define opc_dup_x1		0x5a
#define opc_dup_x2		0x5b
#define opc_dup2		0x5c
#define opc_dup2_x1		0x5d
#define opc_dup2_x2		0x5e
#define opc_swap		0x5f
#define opc_iadd		0x60
#define opc_ladd		0x61
#define opc_fadd		0x62
#define opc_dadd		0x63
#define opc_isub		0x64
#define opc_lsub		0x65
#define opc_fsub		0x66
#define opc_dsub		0x67
#define opc_imul		0x68
#define opc_lmul		0x69
#define opc_fmul		0x6a
#define opc_dmul		0x6b
#define opc_idiv		0x6c
#define opc_ldiv		0x6d
#define opc_fdiv		0x6e
#define opc_ddiv		0x6f
#define opc_irem		0x70
#define opc_lrem		0x71
#define opc_frem		0x72
#define opc_drem		0x73
#define opc_ineg		0x74
#define opc_lneg		0x75
#define opc_fneg		0x76
#define opc_dneg		0x77
#define opc_ishl		0x78
#define opc_lshl		0x79
#define opc_ishr		0x7a
#define opc_lshr		0x7b
#define opc_iushr		0x7c
#define opc_lushr		0x7d
#define opc_iand		0x7e
#define opc_land		0x7f
#define opc_ior			0x80
#define opc_lor			0x81
#define opc_ixor		0x82
#define opc_lxor		0x83
#define opc_iinc		0x84
#define opc_i2l			0x85
#define opc_i2f			0x86
#define opc_i2d			0x87
#define opc_l2i			0x88
#define opc_l2f			0x89
#define opc_l2d			0x8a
#define opc_f2i			0x8b
#define opc_f2l			0x8c
#define opc_f2d			0x8d
#define opc_d2i			0x8e
#define opc_d2l			0x8f
#define opc_d2f			0x90
#define opc_i2b			0x91
#define opc_i2c			0x92
#define opc_i2s			0x93
#define opc_lcmp		0x94
#define opc_fcmpl		0x95
#define opc_fcmpg		0x96
#define opc_dcmpl		0x97
#define opc_dcmpg		0x98
#define opc_ifeq		0x99
#define opc_ifne		0x9a
#define opc_iflt		0x9b
#define opc_ifge		0x9c
#define opc_ifgt		0x9d
#define opc_ifle		0x9e
#define opc_if_icmpeq		0x9f
#define opc_if_icmpne		0xa0
#define opc_if_icmplt		0xa1
#define opc_if_icmpge		0xa2
#define opc_if_icmpgt		0xa3
#define opc_if_icmple		0xa4
#define opc_if_acmpeq		0xa5
#define opc_if_acmpne		0xa6
#define opc_goto		0xa7
#define opc_jsr			0xa8
#define opc_ret			0xa9
#define opc_tableswitch		0xaa
#define opc_lookupswitch	0xab
#define opc_ireturn		0xac
#define opc_lreturn		0xad
#define opc_freturn		0xae
#define opc_dreturn		0xaf
#define opc_areturn		0xb0
#define opc_return		0xb1
#define opc_getstatic		0xb2
#define opc_putstatic		0xb3
#define opc_getfield		0xb4
#define opc_putfield		0xb5
#define opc_invokevirtual	0xb6
#define opc_invokespecial	0xb7
#define opc_invokestatic	0xb8
#define opc_invokeinterface	0xb9
#define opc_new			0xbb
#define opc_newarray		0xbc
#define opc_anewarray		0xbd
#define opc_arraylength		0xbe
#define opc_athrow		0xbf
#define opc_checkcast		0xc0
#define opc_instanceof		0xc1
#define opc_monitorenter	0xc2
#define opc_monitorexit		0xc3
#define opc_wide		0xc4
#define opc_multianewarray	0xc5
#define opc_ifnull		0xc6
#define opc_ifnonnull		0xc7
#define opc_goto_w		0xc8
#define opc_jsr_w		0xc9
#define opc_breakpoint		0xca

#define OPC_LAST_JAVA_OP	0xca

#define opc_bgetfield			0xcc
#define opc_cgetfield			0xcd
#define opc_igetfield			0xd0
#define opc_lgetfield			0xd1
#define opc_sgetfield			0xd2
#define opc_aputfield			0xd3
#define opc_bputfield			0xd4
#define opc_cputfield			0xd5
#define opc_iputfield			0xd8
#define opc_lputfield			0xd9
#define opc_iaccess_0			0xdb
#define opc_iaccess_1			0xdc
#define opc_iaccess_2			0xdd
#define opc_iaccess_3			0xde
#define opc_invokeresolved		0xdf
#define opc_invokespecialresolved	0xe0
#define opc_invokestaticresolved	0xe1
#define opc_invokevfinal		0xe2
#define opc_iload_iload			0xe3
#define opc_iload_iload_N		0xe4
#define opc_return_register_finalizer	0xe5
#define opc_dmac			0xe6
#define opc_iload_0_iconst_N		0xe7
#define opc_iload_1_iconst_N		0xe8
#define opc_iload_2_iconst_N		0xe9
#define opc_iload_3_iconst_N		0xea
#define opc_iload_iconst_N		0xeb
#define opc_iadd_istore_N		0xec
#define opc_isub_istore_N		0xed
#define opc_iand_istore_N		0xee
#define opc_ior_istore_N		0xef
#define opc_ixor_istore_N		0xf0
#define opc_iadd_u4store		0xf1
#define opc_isub_u4store		0xf2
#define opc_iand_u4store		0xf3
#define opc_ior_u4store			0xf4
#define opc_ixor_u4store		0xf5
#define opc_iload_0_iload		0xf6
#define opc_iload_1_iload		0xf7
#define opc_iload_2_iload		0xf8
#define opc_iload_3_iload		0xf9
#define opc_iload_0_iload_N		0xfa
#define opc_iload_1_iload_N		0xfb
#define opc_iload_2_iload_N		0xfc
#define opc_iload_3_iload_N		0xfd

#define H_IREM				0
#define H_IDIV				1
#define H_LDIV				2
#define H_LREM				3
#define H_FREM				4
#define H_DREM				5
#define	H_LDC				6
#define H_NEW				8
#define H_I2F				9
#define H_I2D				10
#define H_L2F				11
#define H_L2D				12
#define H_F2I				13
#define H_F2L				14
#define H_F2D				15
#define H_D2I				16
#define H_D2L				17
#define H_D2F				18
#define H_NEWARRAY			19
#define H_ANEWARRAY			20
#define H_MULTIANEWARRAY		21
#define H_INSTANCEOF			22
#define H_CHECKCAST			23
#define H_AASTORE			24
#define H_APUTFIELD			25
#define H_SYNCHRONIZED_ENTER		26
#define H_SYNCHRONIZED_EXIT		27

#define H_EXIT_TO_INTERPRETER		28

#define H_GETSTATIC			H_EXIT_TO_INTERPRETER
#define H_PUTSTATIC			H_EXIT_TO_INTERPRETER
#define H_JSR				H_EXIT_TO_INTERPRETER
#define H_RET				H_EXIT_TO_INTERPRETER
#define H_ZOMBIE			H_EXIT_TO_INTERPRETER
#define H_MONITOR			H_EXIT_TO_INTERPRETER
#define H_ATHROW			H_EXIT_TO_INTERPRETER

#define H_HANDLE_EXCEPTION		29
#define H_ARRAYBOUND			30
#define H_UNKNOWN			31

#define H_DEBUG_METHODENTRY		32
#define H_DEBUG_METHODEXIT		33
#define H_DEBUG_METHODCALL		34

#define H_INVOKEINTERFACE		35
#define H_INVOKEVIRTUAL			36
#define H_INVOKESTATIC			37
#define H_INVOKESPECIAL			38

#define H_GETFIELD_WORD			39
#define H_GETFIELD_SH			40
#define H_GETFIELD_H			41
#define H_GETFIELD_SB			42
#define H_GETFIELD_DW			43

#define H_PUTFIELD_WORD			44
#define H_PUTFIELD_H			45
#define H_PUTFIELD_B			46
#define H_PUTFIELD_A			47
#define H_PUTFIELD_DW			48

#define H_GETSTATIC_WORD		49
#define H_GETSTATIC_SH			50
#define H_GETSTATIC_H			51
#define H_GETSTATIC_SB			52
#define H_GETSTATIC_DW			53

#define H_PUTSTATIC_WORD		54
#define H_PUTSTATIC_H			55
#define H_PUTSTATIC_B			56
#define H_PUTSTATIC_A			57
#define H_PUTSTATIC_DW			58

#define H_STACK_OVERFLOW		59

#define H_HANDLE_EXCEPTION_NO_REGS	60

unsigned handlers[61];

#define LEAF_STACK_SIZE			200
#define STACK_SPARE			40

#define COMPILER_RESULT_FAILED	1	// Failed to compiled this method
#define COMPILER_RESULT_FATAL	2	// Fatal - dont try compile anything ever again

#include <setjmp.h>

static jmp_buf compiler_error_env;

#ifdef PRODUCT

#define JASSERT(cond, msg)	0
#define J_Unimplemented() longjmp(compiler_error_env, COMPILER_RESULT_FATAL)

#else

#define JASSERT(cond, msg)	do { if (!(cond)) fatal(msg); } while (0)
#define J_Unimplemented()       { report_unimplemented(__FILE__, __LINE__); BREAKPOINT; }

#endif // PRODUCT

#define GET_NATIVE_U2(p)	(*(unsigned short *)(p))

#define GET_JAVA_S1(p)		(((signed char *)(p))[0])
#define GET_JAVA_S2(p)  	((((signed char *)(p))[0] << 8) + (p)[1])
#define GET_JAVA_U2(p)		(((p)[0] << 8) + (p)[1])
#define GET_JAVA_U4(p)		(((p)[0] << 24) + ((p)[1] << 16) + ((p)[2] << 8) + (p)[3])

#define BYTESEX_REVERSE(v) (((v)<<24) | (((v)<<8) & 0xff0000) | (((v)>>8) & 0xff00) | ((v)>>24))
#define BYTESEX_REVERSE_U2(v) (((v)<<8) | ((v)>>8))

typedef struct Thumb2_CodeBuf {
  unsigned size;
  char *sp;
  char *hp;
} Thumb2_CodeBuf;

Thumb2_CodeBuf *thumb2_codebuf;

unsigned bc_stackinfo[THUMB2_MAX_BYTECODE_SIZE];
unsigned locals_info[1000];
unsigned stack[1000];
unsigned r_local[1000];

#ifdef T2EE_PRINT_DISASS
short start_bci[THUMB2_MAX_T2CODE_SIZE];
short end_bci[THUMB2_MAX_T2CODE_SIZE];
#endif

// XXX hardwired constants!
#define ENTRY_FRAME             1
#define INTERPRETER_FRAME       2
#define SHARK_FRAME             3
#define FAKE_STUB_FRAME         4

#include "offsets_arm.s"

#define BC_FLAGS_MASK		0xfc000000
#define BC_VISITED_P1		0x80000000
#define BC_BRANCH_TARGET	0x40000000
#define BC_COMPILED		0x20000000
#define BC_VISITED_P2		0x10000000
#define BC_ZOMBIE		0x08000000
#define BC_BACK_TARGET		0x04000000

#define IS_DEAD(x)	(((x) & BC_VISITED_P1) == 0)
#define IS_ZOMBIE(x)	(((x) & BC_ZOMBIE) || ((x) & BC_VISITED_P2) == 0)

#define LOCAL_MODIFIED		31
#define LOCAL_REF		30
#define LOCAL_DOUBLE		29
#define LOCAL_FLOAT		28
#define LOCAL_LONG		27
#define LOCAL_INT		26
#define LOCAL_ALLOCATED		25

#define LOCAL_COUNT_BITS	10
#define LOCAL_READ_POS		0
#define LOCAL_WRITE_POS		LOCAL_COUNT_BITS

#define LOCAL_READS(x)		(((x) >> LOCAL_READ_POS) & ((1<<LOCAL_COUNT_BITS)-1))
#define LOCAL_WRITES(x)		(((x) >> LOCAL_WRITE_POS) & ((1<<LOCAL_COUNT_BITS)-1))
#define LOCAL_SET_COUNTS(r, w)	(((r) << LOCAL_READ_POS) | (((w) << LOCAL_WRITE_POS)))
#define LOCAL_INC_COUNT(c)	((c) < ((1<<LOCAL_COUNT_BITS)-1) ? (c)+1 : (c))

#define STACK_REGS	4
#define FP_STACK_REGS	4

typedef unsigned	u32;
typedef unsigned	Reg;

#define	ARM_R0		0
#define ARM_R1		1
#define ARM_R2		2
#define ARM_R3		3
#define ARM_R4		4
#define ARM_R5		5
#define ARM_R6		6
#define ARM_R7		7
#define ARM_R8		8
#define ARM_R9		9
#define ARM_R10		10
#define ARM_R11		11
#define ARM_IP		12
#define ARM_SP		13
#define ARM_LR		14
#define ARM_PC		15
#define ARM_CPSR	16	// CPSR in sigcontext
#define ARM_FAULT	17	// fault address in sigcontext

#define CPSR_THUMB_BIT	(1<<5)

#define VFP_S0		32
#define VFP_S1		33
#define VFP_S2		34
#define VFP_S3		35
#define VFP_S4		36
#define VFP_S5		37
#define VFP_S6		38
#define VFP_S7		39

#define VFP_D0		64
#define VFP_D1		65
#define VFP_D2		66
#define VFP_D3		67
#define VFP_D4		68
#define VFP_D5		69
#define VFP_D6		70
#define VFP_D7		71

#define PREGS	5

#define JAZ_V1	ARM_R5
#define JAZ_V2	ARM_R6
#define JAZ_V3	ARM_R7
#define JAZ_V4	ARM_R10
#define JAZ_V5	ARM_R11

#define Rstack		ARM_R4
#define Rlocals		ARM_R7
#define Ristate		ARM_R8
#define Rthread		ARM_R9

#define Rint_stack	ARM_R4
#define Rint_jpc	ARM_R5
#define Rint_istate	ARM_R8

#define IS_ARM_INT_REG(r) ((r) <= ARM_PC)
#define IS_ARM_FP_REG(r) (!IS_ARM_INT_REG(r))

#define I_REGSET	((1<<ARM_R4) | (1<<ARM_R5) | (1<<ARM_R6) | (1<<ARM_R7) | \
			 (1<<ARM_R9) | (1<<ARM_R10) | (1<<ARM_R11))
#define C_REGSET	(1<<ARM_R8)

#define LOG2(n) binary_log2(n)

unsigned binary_log2(unsigned n)
{
  unsigned r = 0;
  if ((n & 0xffff) == 0) r = 16, n >>= 16;
  if ((n & 0xff) == 0) r += 8, n >>= 8;
  if ((n & 0xf) == 0) r += 4, n >>= 4;
  if ((n & 3) == 0) r += 2, n >>= 2;
  if ((n & 1) == 0) r += 1;
  return r;
}

typedef struct Compiled_Method {
    // All entry points aligned on a cache line boundary
    //		.align	CODE_ALIGN
    // slow_entry:				@ callee save interface
    // 		push	{r4, r5, r6, r7, r9, r10, r11, lr}
    // 		bl	fast_entry
    // 		pop	{r4, r5, r6, r7, r9, r10, r11, pc}
    unsigned slow_entry[3];
    unsigned *osr_table;			// pointer to the osr table
    unsigned *exception_table;
    Compiled_Method *next;
    // The next 6 halfword give the register mapping for JAZ_V1 to JAZ_v5
    // This is used when receovering from an exception so we can push
    // the register back into the local variables pool.
    short regusage[6];
    // OSR Entry point:
    // 	R0 = entry point within compiled method
    // 	R1 = locals - 4000 * 4
    // 	R2 = thread
    // 	R3 = locals - 31 * 4
    // osr_entry:
    // 		@ Load each local into it register allocated register
    // 		ldr	<reg>, [R1, #(4000-<local>) * 4]
    //    or	ldr	<reg>, [R3, #(31-<local>) * 4]
    // 		...
    // 		mov	Rthread, R2
    // 		bx	R0
    // 		.align	CODE_ALIGN
    unsigned osr_entry[1];
    // fast_entry:
    // 		push	{r8, lr}
    // 		...	@ The compiled code
    // 		pop	{r8, pc}
    // 		.align	WORD_ALIGN
    // code_handle:				@ from interpreted entry
    // 		.word	slow_entry		@ bottom bit must be set!
    // osr_table:
    // 		.word	<no. of entries>
    // @@@ For bytecode 0 and for each backwards branch target
    // 		.short	<bytecode index>
    // 		.short	<code offset>		@ offset in halfwords from slow_entry
} Compiled_Method;

Compiled_Method *compiled_method_list = 0;
Compiled_Method **compiled_method_list_tail_ptr = &compiled_method_list;

typedef struct Thumb2_Entrypoint {
  unsigned compiled_entrypoint;
  unsigned osr_entry;
} Thumb2_Entrypoint;

typedef struct CodeBuf {
    unsigned short *codebuf;
    unsigned idx;
    unsigned limit;
} CodeBuf;

typedef struct Thumb2_Stack {
    unsigned *stack;
    unsigned depth;
} Thumb2_Stack;

#define IS_SREG(r) ((r) < STACK_REGS)

typedef struct Thumb2_Registers {
    unsigned *r_local;
    unsigned npregs;
    unsigned pregs[PREGS];
    int mapping[PREGS];
} Thumb2_Registers;

typedef struct Thumb2_Info {
    JavaThread *thread;
    methodOop method;
    unsigned *bc_stackinfo;
    unsigned *locals_info;
    jubyte *code_base;
    unsigned code_size;
    CodeBuf *codebuf;
    Thumb2_Stack *jstack;
    Thumb2_Registers *jregs;
    unsigned compiled_return;
    unsigned zombie_bytes;
    unsigned is_leaf;
} Thumb2_Info;

#define IS_INT_SIZE_BASE_TYPE(c) (c=='B' || c=='C' || c=='F' || c=='I' || c=='S' || c=='Z')
#define IS_INT_SIZE_TYPE(c) (IS_INT_SIZE_BASE_TYPE(c) || c == 'L' || c == '[')

static int method_stackchange(jbyte *base)
{
  jbyte c;
  int stackchange = 0;

  c = *base++;
  JASSERT(c == '(', "Invalid signature, missing '('");
  while ((c = *base++) != ')') {
    stackchange -= 1;
    if (c == 'J' || c == 'D') {
      stackchange -= 1;
    } else if (c == '[') {
      do { c = *base++; } while (c == '[');
      if (c == 'L')
	do { c = *base++; } while (c != ';');
    } else if (c == 'L') {
      do { c = *base++; } while (c != ';');
    } else {
      JASSERT(IS_INT_SIZE_BASE_TYPE(c), "Invalid signature, bad arg type");
    }
  }
  JASSERT(c == ')', "Invalid signature, missing ')'");
  c = *base++;
  if (c == 'J' || c == 'D') stackchange += 2;
  else if (c != 'V') {
    stackchange += 1;
    JASSERT(IS_INT_SIZE_TYPE(c), "Invalid signature, bad ret type");
  }
  return stackchange;
}

static void Thumb2_local_info_from_sig(Thumb2_Info *jinfo, methodOop method, jbyte *base)
{
  jbyte c;
  unsigned arg = 0;
  unsigned *locals_info = jinfo->locals_info;
  unsigned local_info;

  if (!method->is_static()) locals_info[arg++] = 1 << LOCAL_REF;
  c = *base++;
  JASSERT(c == '(', "Invalid signature, missing '('");
  while ((c = *base++) != ')') {
    local_info = 1 << LOCAL_INT;
    if (c == 'J') local_info = 1 << LOCAL_LONG;
    else if (c == 'D') local_info = 1 << LOCAL_DOUBLE;
    else if (c == '[') {
      local_info = 1 << LOCAL_REF;
      do { c = *base++; } while (c == '[');
      if (c == 'L')
	do { c = *base++; } while (c != ';');
    } else if (c == 'L') {
      local_info = 1 << LOCAL_REF;
      do { c = *base++; } while (c != ';');
    } else {
      JASSERT(IS_INT_SIZE_BASE_TYPE(c), "Invalid signature, bad arg type");
    }
    locals_info[arg++] = local_info;
  }
}

#define T_UNDEFINED_32	0xf7f0a000
#define T_UNDEFINED_16	0xde00

static const char *local_types[] = { "int", "long", "float", "double", "ref" };

#ifdef T2EE_PRINT_DISASS
void Thumb2_disass(Thumb2_Info *jinfo)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;
  unsigned *locals_info = jinfo->locals_info;
  unsigned nlocals = jinfo->method->max_locals();
  int bci = 0;
  int last_bci = -1;
  int start_b, end_b;
  unsigned nodisass;

  struct disassemble_info info;
  unsigned short *codebuf = jinfo->codebuf->codebuf;
  unsigned idx, compiled_len;

#if 0
  printf("Local Variable Usage\n");
  printf("====================\n");
  for (idx = 0; idx < nlocals; idx++) {
    unsigned linfo = locals_info[idx];
    unsigned typ = (linfo >> LOCAL_INT) & 0x1f;

    printf("Local %d, type = %s (%x)", idx, typ ? local_types[LOG2(typ)] : "!!!unknown!!!", typ);
    if (linfo & (1 << LOCAL_MODIFIED)) printf(", modified");
    if (idx < (unsigned)jinfo->method->size_of_parameters()) printf(", parameter");
    putchar('\n');
  }
#endif

  init_disassemble_info(&info, stdout, (fprintf_ftype)fprintf);
  info.arch = bfd_arch_arm;
  disassemble_init_for_target(&info);
  info.endian = BFD_ENDIAN_LITTLE;
  info.endian_code = BFD_ENDIAN_LITTLE;
  info.buffer = (bfd_byte *)codebuf;
  info.buffer_vma = (bfd_vma)codebuf;
  info.buffer_length = jinfo->codebuf->idx * sizeof(short);
  info.disassembler_options = (char *)"force-thumb";

  compiled_len = jinfo->codebuf->idx * 2;
  for (idx = 0; idx < compiled_len; ) {
    nodisass = 0;
    start_b = start_bci[idx/2];
    end_b = end_bci[idx/2];
    if (start_b != -1) {
      last_bci != -1;
      for (bci = start_b; bci < end_b; ) {
	unsigned stackinfo = bc_stackinfo[bci];
	unsigned opcode;
	int len;

	if (stackinfo & BC_BRANCH_TARGET)
	  printf("----- Basic Block -----\n");
	JASSERT(bci > last_bci, "disass not advancing");
	last_bci = bci;
	printf("%c%4d : ", (stackinfo & BC_VISITED_P1) ? ' ' : '?', bci);
	opcode = code_base[bci];
	if (opcode > OPC_LAST_JAVA_OP) {
	  if (Bytecodes::is_defined((Bytecodes::Code)opcode))
	    opcode = (unsigned)Bytecodes::java_code((Bytecodes::Code)opcode);
	}
	len = Bytecodes::length_for((Bytecodes::Code)opcode);
	if (len <= 0) len = Bytecodes::special_length_at((address)(code_base+bci), (address)(code_base+code_size));
	switch (opcode) {
	  case opc_tableswitch: {
	    int nbci = (bci & ~3) + 4;
	    int low, high;
	    unsigned w;
	    unsigned *table;
	    int def;
	    unsigned n, i;

	    printf("%02x ", opcode);
	    for (int i = 1; i < 5; i++)
	      printf("   ");
	    printf("%s\n", Bytecodes::name((Bytecodes::Code)opcode));
	    printf("\t%d bytes padding\n", nbci - (bci+1));
	    w = *(unsigned int *)(code_base + nbci + 4);
	    low = (int)BYTESEX_REVERSE(w);
	    w = *(unsigned int *)(code_base + nbci + 8);
	    high = (int)BYTESEX_REVERSE(w);
	    w = *(unsigned int *)(code_base + nbci + 0);
	    def = (int)BYTESEX_REVERSE(w);
	    table = (unsigned int *)(code_base + nbci + 12);
	    printf("\tdefault:\t0x%08x\n", def);
	    printf("\tlow:\t\t0x%08x\n", low);
	    printf("\thigh:\t\t0x%08x\n", high);
	    n = high - low + 1;
	    while (low <= high) {
	      int off;

	      w = *table++;
	      off = (int)BYTESEX_REVERSE(w);
	      printf("\toffset %d:\t0x%08x\n", low, off);
	      low++;
	    }
	    bci += len;
	    for (i = 0; i < 4; i++) {
	      printf("0x%08x:\t", (int)codebuf+idx);
	      {
		int len = print_insn_little_arm((bfd_vma)codebuf+idx, &info);
		if (len == -1) len = 2;
		idx += len;
		putchar('\n');
	      }
	    }
	    for (i = 0; i < n; i++) {
	      printf("0x%08x:\t.short\t0x%04x\n", (int)codebuf+idx, *(short *)((int)codebuf + idx));
	      idx += 2;
	    }
	    nodisass = 1;
	    break;
	  }
	  case opc_lookupswitch: {
	    unsigned w;
	    unsigned nbci = (bci & ~3) + 4;;
	    int def;
	    int npairs;	// The Java spec says signed but must be >= 0??
	    unsigned *table;

	    printf("%02x ", opcode);
	    for (int i = 1; i < 5; i++)
	      printf("   ");
	    printf("%s\n", Bytecodes::name((Bytecodes::Code)opcode));
	    printf("\t%d bytes padding\n", nbci - (bci+1));

	    w = *(unsigned int *)(code_base + nbci + 0);
	    def = (int)BYTESEX_REVERSE(w);
	    w = *(unsigned int *)(code_base + nbci + 4);
	    npairs = (int)BYTESEX_REVERSE(w);
	    table = (unsigned int *)(code_base + nbci + 8);
	    printf("\tdefault:\t0x%08x\n", def);
	    printf("\tnpairs:\t\t0x%08x\n", npairs);
	    for (int i = 0; i < npairs; i++) {
	      unsigned match, off;
	      w = table[0];
	      match = BYTESEX_REVERSE(w);
	      w = table[1];
	      table += 2;
	      off = BYTESEX_REVERSE(w);
	      printf("\t  match: 0x%08x, offset: 0x%08x\n", match, off);
	    }
	    break;
	  }

	  default:
	    for (int i = 0; i < 5; i++) {
	      if (i < len)
		printf("%02x ", code_base[bci+i]);
	      else
		printf("   ");
	    }
	    printf("%s\n", Bytecodes::name((Bytecodes::Code)code_base[bci]));
	    break;
	}
	bci += len;
      }
    }
    if (!nodisass) {
      printf("0x%08x:\t", (int)codebuf+idx);
      {
	int len;
	unsigned s1, s2;

	s1 = *(unsigned short *)((int)codebuf + idx);
	s2 = *(unsigned short *)((int)codebuf + idx + 2);
	if (s1 == T_UNDEFINED_16 || ((s1 << 16) + s2) == T_UNDEFINED_32) {
	  if (s1 == T_UNDEFINED_16) {
	    printf("undefined (0xde00) - UNPATCHED BRANCH???");
	    len = 2;
	  } else {
	    printf("undefined (0xf7f0a000) - UNPATCHED BRANCH???");
	    len = 4;
	  }
	} else {
	  len = print_insn_little_arm((bfd_vma)codebuf+idx, &info);
	  if (len == -1) len = 2;
	  idx += len;
	}
	putchar('\n');
      }
    }
  }
}
#endif

#define BCI(len, pop, push, special, islocal, islocal_n, isstore, local_n, local_type) \
	((len) | ((pop)<<3) | ((push)<<6) | (unsigned)((special) << 31) | ((islocal) << 30) | ((islocal_n) << 29) | ((isstore) << 28) | ((local_n) << 9) | ((local_type) << 11))

#define BCI_LEN(x) 	((x) & 7)
#define BCI_POP(x) 	(((x)>>3) & 7)
#define BCI_PUSH(x) 	(((x)>>6) & 7)
#define BCI_LOCAL_N(x)	(((x)>>9) & 3)
#define BCI_LOCAL_TYPE(x) (((x) >> 11) & 7)

#define BCI_TYPE_INT	0
#define BCI_TYPE_LONG	1
#define BCI_TYPE_FLOAT	2
#define BCI_TYPE_DOUBLE	3
#define BCI_TYPE_REF	4

#define BCI_SPECIAL(x) 	((x) & 0x80000000)
#define BCI_ISLOCAL(x)	((x) & 0x40000000)
#define BCI_ISLOCAL_N(x) ((x) & 0x20000000)
#define BCI_ISSTORE(x)	((x) & 0x10000000)

static const unsigned bcinfo[256] = {
	BCI(1, 0, 0, 0, 0, 0, 0, 0, 0),	// nop
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// aconst_null
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_m1
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_0
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_1
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_2
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_3
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_4
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// iconst_5
	BCI(1, 0, 2, 0, 0, 0, 0, 0, 0),	// lconst_0
	BCI(1, 0, 2, 0, 0, 0, 0, 0, 0),	// lconst_1
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// fconst_0
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// fconst_1
	BCI(1, 0, 1, 0, 0, 0, 0, 0, 0),	// fconst_2
	BCI(1, 0, 2, 0, 0, 0, 0, 0, 0),	// dconst_0
	BCI(1, 0, 2, 0, 0, 0, 0, 0, 0),	// dconst_1
	BCI(2, 0, 1, 0, 0, 0, 0, 0, 0),	// bipush
	BCI(3, 0, 1, 0, 0, 0, 0, 0, 0),	// bipush
	BCI(2, 0, 1, 0, 0, 0, 0, 0, 0),	// ldc
	BCI(3, 0, 1, 0, 0, 0, 0, 0, 0),	// ldc_w
	BCI(3, 0, 2, 0, 0, 0, 0, 0, 0),	// ldc2_w
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_INT),	// iload
	BCI(2, 0, 2, 0, 1, 0, 0, 0, BCI_TYPE_LONG),	// lload
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_FLOAT),	// fload
	BCI(2, 0, 2, 0, 1, 0, 0, 0, BCI_TYPE_DOUBLE),	// dload
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_REF),	// aload
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_INT),	// iload_0
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_INT),	// iload_1
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_INT),	// iload_2
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_INT),	// iload_3
	BCI(1, 0, 2, 0, 1, 1, 0, 0, BCI_TYPE_LONG),	// lload_0
	BCI(1, 0, 2, 0, 1, 1, 0, 1, BCI_TYPE_LONG),	// lload_1
	BCI(1, 0, 2, 0, 1, 1, 0, 2, BCI_TYPE_LONG),	// lload_2
	BCI(1, 0, 2, 0, 1, 1, 0, 3, BCI_TYPE_LONG),	// lload_3
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_FLOAT),	// fload_0
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_FLOAT),	// fload_1
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_FLOAT),	// fload_2
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_FLOAT),	// fload_3
	BCI(1, 0, 2, 0, 1, 1, 0, 0, BCI_TYPE_DOUBLE),	// dload_0
	BCI(1, 0, 2, 0, 1, 1, 0, 1, BCI_TYPE_DOUBLE),	// dload_1
	BCI(1, 0, 2, 0, 1, 1, 0, 2, BCI_TYPE_DOUBLE),	// dload_2
	BCI(1, 0, 2, 0, 1, 1, 0, 3, BCI_TYPE_DOUBLE),	// dload_3
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_REF),	// aload_0
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_REF),	// aload_1
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_REF),	// aload_2
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_REF),	// aload_3
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iaload
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// laload
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// faload
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// daload
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// aaload
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// baload
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// caload
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// saload
	BCI(2, 1, 0, 0, 1, 0, 1, 0, BCI_TYPE_INT),	// istore
	BCI(2, 2, 0, 0, 1, 0, 1, 0, BCI_TYPE_LONG),	// lstore
	BCI(2, 1, 0, 0, 1, 0, 1, 0, BCI_TYPE_FLOAT),	// fstore
	BCI(2, 2, 0, 0, 1, 0, 1, 0, BCI_TYPE_DOUBLE),	// dstore
	BCI(2, 1, 0, 0, 1, 0, 1, 0, BCI_TYPE_REF),	// astore
	BCI(1, 1, 0, 0, 1, 1, 1, 0, BCI_TYPE_INT),	// istore_0
	BCI(1, 1, 0, 0, 1, 1, 1, 1, BCI_TYPE_INT),	// istore_1
	BCI(1, 1, 0, 0, 1, 1, 1, 2, BCI_TYPE_INT),	// istore_2
	BCI(1, 1, 0, 0, 1, 1, 1, 3, BCI_TYPE_INT),	// istore_3
	BCI(1, 2, 0, 0, 1, 1, 1, 0, BCI_TYPE_LONG),	// lstore_0
	BCI(1, 2, 0, 0, 1, 1, 1, 1, BCI_TYPE_LONG),	// lstore_1
	BCI(1, 2, 0, 0, 1, 1, 1, 2, BCI_TYPE_LONG),	// lstore_2
	BCI(1, 2, 0, 0, 1, 1, 1, 3, BCI_TYPE_LONG),	// lstore_3
	BCI(1, 1, 0, 0, 1, 1, 1, 0, BCI_TYPE_FLOAT),	// fstore_0
	BCI(1, 1, 0, 0, 1, 1, 1, 1, BCI_TYPE_FLOAT),	// fstore_1
	BCI(1, 1, 0, 0, 1, 1, 1, 2, BCI_TYPE_FLOAT),	// fstore_2
	BCI(1, 1, 0, 0, 1, 1, 1, 3, BCI_TYPE_FLOAT),	// fstore_3
	BCI(1, 2, 0, 0, 1, 1, 1, 0, BCI_TYPE_DOUBLE),	// dstore_0
	BCI(1, 2, 0, 0, 1, 1, 1, 1, BCI_TYPE_DOUBLE),	// dstore_1
	BCI(1, 2, 0, 0, 1, 1, 1, 2, BCI_TYPE_DOUBLE),	// dstore_2
	BCI(1, 2, 0, 0, 1, 1, 1, 3, BCI_TYPE_DOUBLE),	// dstore_3
	BCI(1, 1, 0, 0, 1, 1, 1, 0, BCI_TYPE_REF),	// astore_0
	BCI(1, 1, 0, 0, 1, 1, 1, 1, BCI_TYPE_REF),	// astore_1
	BCI(1, 1, 0, 0, 1, 1, 1, 2, BCI_TYPE_REF),	// astore_2
	BCI(1, 1, 0, 0, 1, 1, 1, 3, BCI_TYPE_REF),	// astore_3
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// iastore
	BCI(1, 4, 0, 0, 0, 0, 0, 0, 0),	// dastore
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// fastore
	BCI(1, 4, 0, 0, 0, 0, 0, 0, 0),	// lastore
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// aastore
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// bastore
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// castore
	BCI(1, 3, 0, 0, 0, 0, 0, 0, 0),	// sastore
	BCI(1, 1, 0, 0, 0, 0, 0, 0, 0),	// pop
	BCI(1, 2, 0, 0, 0, 0, 0, 0, 0),	// pop2
	BCI(1, 1, 2, 0, 0, 0, 0, 0, 0),	// dup
	BCI(1, 2, 3, 0, 0, 0, 0, 0, 0),	// dup_x1
	BCI(1, 3, 4, 0, 0, 0, 0, 0, 0),	// dup_x2
	BCI(1, 2, 4, 0, 0, 0, 0, 0, 0),	// dup2
	BCI(1, 3, 5, 0, 0, 0, 0, 0, 0),	// dup2_x1
	BCI(1, 4, 6, 0, 0, 0, 0, 0, 0),	// dup2_x2
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// swap
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iadd
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// ladd
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fadd
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// dadd
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// isub
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// lsub
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fsub
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// dsub
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// imul
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// lmul
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fmul
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// dmul
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// idiv
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// ldiv
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fdiv
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// ddiv
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// irem
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// lrem
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// frem
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// drem
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// ineg
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// lneg
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// fneg
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// dneg
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ishl
	BCI(1, 3, 2, 0, 0, 0, 0, 0, 0),	// lshl
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ishr
	BCI(1, 3, 2, 0, 0, 0, 0, 0, 0),	// lshr
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iushr
	BCI(1, 3, 2, 0, 0, 0, 0, 0, 0),	// lushr
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iand
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// land
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ior
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// lor
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ixor
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// lxor
	BCI(3, 0, 0, 0, 1, 0, 1, 0, BCI_TYPE_INT),	// iinc
	BCI(1, 1, 2, 0, 0, 0, 0, 0, 0),	// i2l
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// i2f
	BCI(1, 1, 2, 0, 0, 0, 0, 0, 0),	// i2d
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// l2i
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// l2f
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// l2d
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// f2i
	BCI(1, 1, 2, 0, 0, 0, 0, 0, 0),	// f2l
	BCI(1, 1, 2, 0, 0, 0, 0, 0, 0),	// f2d
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// d2i
	BCI(1, 2, 2, 0, 0, 0, 0, 0, 0),	// d2l
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// d2f
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// i2b
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// i2c
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// i2s
	BCI(1, 4, 1, 0, 0, 0, 0, 0, 0),	// lcmp
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fcmpl
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// fcmpg
	BCI(1, 4, 1, 0, 0, 0, 0, 0, 0),	// dcmpl
	BCI(1, 4, 1, 0, 0, 0, 0, 0, 0),	// dcmpg
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifeq
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifne
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// iflt
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifge
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifgt
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifle
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmpeq
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmpne
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmplt
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmpge
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmpgt
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_icmple
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_acmpeq
	BCI(3, 2, 0, 1, 0, 0, 0, 0, 0),	// if_acmpne
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// goto
	BCI(3, 0, 1, 1, 0, 0, 0, 0, 0),	// jsr
	BCI(2, 0, 0, 1, 0, 0, 0, 0, 0),	// ret
	BCI(0, 1, 0, 1, 0, 0, 0, 0, 0),	// tableswitch
	BCI(0, 1, 0, 1, 0, 0, 0, 0, 0),	// lookupswitch
	BCI(1, 1, 0, 1, 0, 0, 0, 0, 0),	// ireturn
	BCI(1, 2, 0, 1, 0, 0, 0, 0, 0),	// lreturn
	BCI(1, 1, 0, 1, 0, 0, 0, 0, 0),	// freturn
	BCI(1, 2, 0, 1, 0, 0, 0, 0, 0),	// dreturn
	BCI(1, 1, 0, 1, 0, 0, 0, 0, 0),	// areturn
	BCI(1, 0, 0, 1, 0, 0, 0, 0, 0),	// return
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// getstatic
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// putstatic
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// getfield
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// putfield
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokevirtual
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokespecial
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokestatic
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokeinterface
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// xxxunusedxxx
	BCI(3, 0, 1, 0, 0, 0, 0, 0, 0),	// new
	BCI(2, 1, 1, 0, 0, 0, 0, 0, 0),	// newarray
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// anewarray
	BCI(1, 1, 1, 0, 0, 0, 0, 0, 0),	// arraylength
	BCI(1, 1, 1, 1, 0, 0, 0, 0, 0),	// athrow
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// checkcast
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// instanceof
	BCI(1, 1, 0, 0, 0, 0, 0, 0, 0),	// monitorenter
	BCI(1, 1, 0, 0, 0, 0, 0, 0, 0),	// monitorexit
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// wide
	BCI(4, 0, 0, 1, 0, 0, 0, 0, 0),	// multianewarray
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifnull
	BCI(3, 1, 0, 1, 0, 0, 0, 0, 0),	// ifnonnull
	BCI(5, 0, 0, 1, 0, 0, 0, 0, 0),	// goto_w
	BCI(5, 0, 0, 1, 0, 0, 0, 0, 0),	// jsr_w
	BCI(1, 0, 0, 1, 0, 0, 0, 0, 0),	// breakpoint
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xcb
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// bgetfield
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// cgetfield
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xce
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xcf
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// igetfield
	BCI(3, 1, 2, 0, 0, 0, 0, 0, 0),	// lgetfield
	BCI(3, 1, 1, 0, 0, 0, 0, 0, 0),	// sgetfield
	BCI(3, 2, 0, 0, 0, 0, 0, 0, 0),	// aputfield
	BCI(3, 2, 0, 0, 0, 0, 0, 0, 0),	// bputfield
	BCI(3, 2, 0, 0, 0, 0, 0, 0, 0),	// cputfield
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xd6
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xd7
	BCI(3, 2, 0, 0, 0, 0, 0, 0, 0),	// iputfield
	BCI(3, 3, 0, 0, 0, 0, 0, 0, 0),	// lputfield
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// unused 0xda
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_REF),	// iaccess_0
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_REF),	// iaccess_1
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_REF),	// iaccess_2
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_REF),	// iaccess_3
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokeresolved
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokespecialresolved
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokestaticresolved
	BCI(3, 0, 0, 1, 0, 0, 0, 0, 0),	// invokevfinal
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_INT),	// iload_iload
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_INT),	// iload_iload_N
	BCI(1, 0, 0, 1, 0, 0, 0, 0, 0),	// return_register_finalizer
	BCI(1, 4, 2, 0, 0, 0, 0, 0, 0),	// dmac
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_INT),	// iload_0_iconst_N
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_INT),	// iload_1_iconst_N
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_INT),	// iload_2_iconst_N
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_INT),	// iload_3_iconst_N
	BCI(2, 0, 1, 0, 1, 0, 0, 0, BCI_TYPE_INT),	// iload_iconst_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iadd_istore_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// isub_istore_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iand_istore_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ior_istore_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ixor_istore_N
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iadd_u4store
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// isub_u4store
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// iand_u4store
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ior_u4store
	BCI(1, 2, 1, 0, 0, 0, 0, 0, 0),	// ixor_u4store
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_INT),	// iload_0_iload
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_INT),	// iload_1_iload
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_INT),	// iload_2_iload
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_INT),	// iload_3_iload
	BCI(1, 0, 1, 0, 1, 1, 0, 0, BCI_TYPE_INT),	// iload_0_iload_N
	BCI(1, 0, 1, 0, 1, 1, 0, 1, BCI_TYPE_INT),	// iload_1_iload_N
	BCI(1, 0, 1, 0, 1, 1, 0, 2, BCI_TYPE_INT),	// iload_2_iload_N
	BCI(1, 0, 1, 0, 1, 1, 0, 3, BCI_TYPE_INT),	// iload_3_iload_N
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// impdep1
	BCI(0, 0, 0, 1, 0, 0, 0, 0, 0),	// impdep2
};

void Thumb2_pass1(Thumb2_Info *jinfo, unsigned bci)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;
  unsigned *locals_info = jinfo->locals_info;
  //constantPoolCacheOop cp = jinfo->method->constants()->cache();

  bc_stackinfo[bci] |= BC_BRANCH_TARGET;
  while (bci < code_size) {
    unsigned stackinfo = bc_stackinfo[bci];
    unsigned bytecodeinfo;
    unsigned opcode;

    if (stackinfo & BC_VISITED_P1) break;
    bc_stackinfo[bci] = (stackinfo & BC_FLAGS_MASK) | BC_VISITED_P1;
    opcode = code_base[bci];
//	printf("bci = 0x%04x, opcode = 0x%02x (%s)", bci, opcode,  Bytecodes::name((Bytecodes::Code)opcode));
    bytecodeinfo = bcinfo[opcode];
    if (!BCI_SPECIAL(bytecodeinfo)) {
      bci += BCI_LEN(bytecodeinfo);
      continue;
    }

    switch (opcode) {

      case opc_goto: {
	int off = GET_JAVA_S2(code_base+bci+1);
	bci += off;
	bc_stackinfo[bci] |= BC_BRANCH_TARGET;
	if (off < 0) bc_stackinfo[bci] |= BC_BACK_TARGET;
	break;
      }
      case opc_goto_w: {
	int off = GET_JAVA_U4(code_base+bci+1);
	bci += off;
	bc_stackinfo[bci] |= BC_BRANCH_TARGET;
	if (off < 0) bc_stackinfo[bci] |= BC_BACK_TARGET;
	break;
      }

      case opc_if_icmpeq:
      case opc_if_icmpne:
      case opc_if_icmplt:
      case opc_if_icmpge:
      case opc_if_icmpgt:
      case opc_if_icmple:
      case opc_if_acmpeq:
      case opc_if_acmpne:
      case opc_ifeq:
      case opc_ifne:
      case opc_iflt:
      case opc_ifge:
      case opc_ifgt:
      case opc_ifle:
      case opc_ifnull:
      case opc_ifnonnull: {
	int off = GET_JAVA_S2(code_base+bci+1);
	if (off < 0) bc_stackinfo[bci+off] |= BC_BACK_TARGET;
	Thumb2_pass1(jinfo, bci + off);
	bci += 3;
	break;
      }

      case opc_jsr: {
	int off = GET_JAVA_S2(code_base+bci+1);
	if (off < 0) bc_stackinfo[bci+off] |= BC_BACK_TARGET;
	Thumb2_pass1(jinfo, bci + off);
	bci += 3;
	break;
      }
      case opc_jsr_w: {
	int off = GET_JAVA_U4(code_base+bci+1);
	if (off < 0) bc_stackinfo[bci+off] |= BC_BACK_TARGET;
	Thumb2_pass1(jinfo, bci + off);
	bci += 5;
	break;
      }

      case opc_ireturn:
      case opc_lreturn:
      case opc_freturn:
      case opc_dreturn:
      case opc_areturn:
      case opc_return:
      case opc_return_register_finalizer:
      case opc_ret:
      case opc_athrow:
	// The test for BC_VISITED_P1 above will break out of the loop!!!
	break;

      case opc_tableswitch: {
	int low, high;
	unsigned w;
	unsigned *table;
	unsigned nbci;
	int def;

	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 8);
	low = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 12);
	high = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 4);
	def = (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 16);

	while (low <= high) {
	  int off;
	  w = *table++;
	  off = (int)BYTESEX_REVERSE(w);
	  if (off < 0) bc_stackinfo[bci+off] |= BC_BACK_TARGET;
	  Thumb2_pass1(jinfo, bci + off);
	  low++;
	}

	bci += def;
	bc_stackinfo[bci] |= BC_BRANCH_TARGET;
	if (def < 0) bc_stackinfo[bci] |= BC_BACK_TARGET;
	break;
      }

      case opc_lookupswitch: {
	unsigned w;
	unsigned nbci;
	int def;
	int npairs;	// The Java spec says signed but must be >= 0??
	unsigned *table;

	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 4);
	def = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 8);
	npairs = (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 16);

	for (int i = 0; i < npairs; i++) {
	  int off;
	  w = *table;
	  table += 2;
	  off = (int)BYTESEX_REVERSE(w);
	  if (off < 0) bc_stackinfo[bci+off] |= BC_BACK_TARGET;
	  Thumb2_pass1(jinfo, bci + off);
	}

	bci += def;
	bc_stackinfo[bci] |= BC_BRANCH_TARGET;
	if (def < 0) bc_stackinfo[bci] |= BC_BACK_TARGET;
	break;
      }

      case opc_getstatic:
      case opc_putstatic:
      case opc_getfield:
      case opc_putfield: {
	bci += 3;
	break;
      }

      case opc_invokeresolved:
      case opc_invokespecialresolved:
      case opc_invokestaticresolved:
      case opc_invokevfinal:
      case opc_invokevirtual:
      case opc_invokespecial:
      case opc_invokestatic:
	jinfo->is_leaf = 0;
	bci += 3;
	break;

      case opc_invokeinterface:
	jinfo->is_leaf = 0;
	bci += 5;
	break;

      case opc_multianewarray:
	bci += 4;
	break;

      case opc_wide:
	opcode = code_base[bci+1];
	if (opcode == opc_iinc) {
	  bci += 6;
	} else {
	  bci += 4;
	}
	break;

      default:
	opcode = code_base[bci];
	fatal1("Undefined opcode %d\n", opcode);
	break;
    }
  }
}

#ifdef ZOMBIE_DETECTION
int Thumb2_is_zombie(Thumb2_Info *jinfo, unsigned bci)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned bytecodeinfo;
  unsigned opcode;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;

  do {
    opcode = code_base[bci];
    // Short circuit exit - commented out because even if it has been executed
    // we treat throw, jsr, and ret as zombies because they will call out to the
    // interpreter.
    // if (opcode > OPC_LAST_JAVA_OP) return 0;
    bytecodeinfo = bcinfo[opcode];
    if (!BCI_SPECIAL(bytecodeinfo)) {
	bci += BCI_LEN(bytecodeinfo);
#if 0
	if (opcode >= opc_iload_iload) {
	  opcode = code_base[bci];
	  bci += BCI_LEN(bcinfo[opcode]);
	} else if (BCI_ISLOCAL(bytecodeinfo)) {
	  if (opcode == opc_iload || (opcode >= opc_iload_0 && opcode <= opc_iload_3)) {
	    opcode = code_base[bci];
	    if (opcode == opc_iload || (opcode >= opc_iload_0 && opcode <= opc_iload_3) ||
					(opcode >= opc_iconst_m1 && opcode <= opc_iconst_5)) {
		printf("found new zombie at %d\n", bci);
		return 1;
	    }
	  }
	} else if (opcode == opc_iadd || opcode == opc_isub ||
		      opcode == opc_iand || opcode == opc_ior || opcode == opc_ixor) {
	    opcode = code_base[bci];
	    if (opcode == opc_istore || (opcode >= opc_istore_0 && opcode <= opc_istore_3)) {
		printf("found new zombie at %d\n", bci);
		return 1;
	    }
	}
#endif
    } else {
      switch (opcode) {
	case opc_goto:
	case opc_goto_w:
	case opc_ifeq:
	case opc_ifne:
	case opc_iflt:
	case opc_ifge:
	case opc_ifgt:
	case opc_ifle:
	case opc_ifnull:
	case opc_ifnonnull:
	case opc_if_icmpeq:
	case opc_if_icmpne:
	case opc_if_icmplt:
	case opc_if_icmpge:
	case opc_if_icmpgt:
	case opc_if_icmple:
	case opc_if_acmpeq:
	case opc_if_acmpne:
	case opc_tableswitch:
	case opc_lookupswitch:
	  return 0;
	case opc_ireturn:
	case opc_lreturn:
	case opc_freturn:
	case opc_dreturn:
	case opc_areturn:
	case opc_return:
	case opc_return_register_finalizer:
	    return 0;
	case opc_jsr:
	case opc_jsr_w:
	case opc_ret:
	case opc_athrow:
	    return 1;
	case opc_invokeinterface:
	case opc_invokevirtual:
	case opc_invokespecial:
	case opc_invokestatic:
	case opc_putfield:
	case opc_getfield:
	case opc_putstatic:
	case opc_getstatic: {
	  constantPoolCacheOop  cp = jinfo->method->constants()->cache();
	  ConstantPoolCacheEntry* cache;
	  int index = GET_NATIVE_U2(code_base+bci+1);

	  cache = cp->entry_at(index);
	  if (!cache->is_resolved((Bytecodes::Code)opcode)) return 1;
	  bci += 3;
	  if (opcode == opc_invokeinterface) bci += 2;
	  break;

	}
	case opc_invokeresolved:
	case opc_invokespecialresolved:
	case opc_invokestaticresolved:
	case opc_invokevfinal:
	  bci += 3;
	  break;

	case opc_multianewarray:
	  bci += 4;
	  break;

	case opc_wide:
	  opcode = code_base[bci+1];
	  if (opcode == opc_iinc) {
	    bci += 6;
	  } else {
	    bci += 4;
	  }
	  break;

	default:
	  opcode = code_base[bci];
	  fatal1("Undefined opcode %d\n", opcode);
	  break;
      }
    }
    if (bci >= code_size) break;
  } while (!(bc_stackinfo[bci] & BC_BRANCH_TARGET));
  return 0;
}
#endif // ZOMBIT_DETECTION

void Thumb2_RegAlloc(Thumb2_Info *jinfo)
{
  unsigned *locals_info = jinfo->locals_info;
  unsigned i, j;
  unsigned linfo;
  unsigned score, max_score;
  unsigned local;
  unsigned nlocals = jinfo->method->max_locals();
  unsigned *pregs = jinfo->jregs->pregs;
  unsigned npregs = jinfo->jregs->npregs;

  for (i = 0; i < npregs; i++) jinfo->jregs->mapping[i] = -1;
  for (i = 0; i < npregs; i++) {
    max_score = 0;
    for (j = 0; j < nlocals; j++) {
      linfo = locals_info[j];

      if (linfo & ((1<<LOCAL_ALLOCATED)|(1<<LOCAL_DOUBLE))) continue;
      score = LOCAL_READS(linfo) + LOCAL_WRITES(linfo);
      if (linfo & (1<<LOCAL_MODIFIED)) score = (score+1) >> 2;
      if (linfo & (1<<LOCAL_REF)) score = score - (score >> 2);
      if (linfo & (1<<LOCAL_LONG)) score = (score+1) >> 2;
      if (score > max_score) max_score = score, local = j;
    }
    if (max_score < 2) break;
    locals_info[local] |= 1<<LOCAL_ALLOCATED;
    jinfo->jregs->r_local[local] = pregs[i];
    jinfo->jregs->mapping[i] = local;
  }
#ifdef T2EE_PRINT_REGUSAGE
  if (t2ee_print_regusage) {
    printf("Regalloc: %d physical registers allocated as follows\n", npregs);
    for (j = 0; j < nlocals; j++) {
      unsigned r = jinfo->jregs->r_local[j];
      if (r) {
	unsigned typ = (locals_info[j] >> LOCAL_INT) & 0x1f;
	printf("  ARM Reg R%d -> local %d (type = %s)\n", r, j, local_types[LOG2(typ)]);
      }
    }
  }
#endif
}

void Thumb2_pass2(Thumb2_Info *jinfo, unsigned stackdepth, unsigned bci)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;
  unsigned *locals_info = jinfo->locals_info;
  unsigned check_zombie = 0;
  //constantPoolCacheOop cp = jinfo->method->constants()->cache();

  while (bci < code_size) {
    unsigned stackinfo = bc_stackinfo[bci];
    unsigned bytecodeinfo;
    unsigned opcode;

    if (stackinfo & BC_VISITED_P2) break;
    JASSERT((int)stackdepth >= 0, "stackdepth < 0!!");
    bc_stackinfo[bci] = (stackinfo & BC_FLAGS_MASK) | stackdepth | BC_VISITED_P2;
#ifdef ZOMBIE_DETECTION
    if (check_zombie || (stackinfo & BC_BRANCH_TARGET)) {
      if (Thumb2_is_zombie(jinfo, bci)) {
	printf("zombie code at %d\n", bci);
	bc_stackinfo[bci] |= BC_ZOMBIE;
	return;
      }
      check_zombie = 0;
    }
#endif
    opcode = code_base[bci];
//	printf("bci = 0x%04x, opcode = 0x%02x (%s), stackdepth = %d\n", bci, opcode,  Bytecodes::name((Bytecodes::Code)opcode), stackdepth);
    bytecodeinfo = bcinfo[opcode];
    if (!BCI_SPECIAL(bytecodeinfo)) {
      if (BCI_ISLOCAL(bytecodeinfo)) {
	unsigned local = BCI_LOCAL_N(bytecodeinfo);
	unsigned local_type = BCI_LOCAL_TYPE(bytecodeinfo) + LOCAL_INT;
	unsigned local_modified = 0;
	unsigned linfo;
	unsigned read_count, write_count;

	if (!BCI_ISLOCAL_N(bytecodeinfo)) local = code_base[bci+1];
	if (BCI_ISSTORE(bytecodeinfo)) local_modified = 1U << LOCAL_MODIFIED;
	linfo = locals_info[local];
	read_count = LOCAL_READS(linfo);
	write_count = LOCAL_WRITES(linfo);
	if (local_modified)
	  write_count = LOCAL_INC_COUNT(write_count);
	else
	  read_count = LOCAL_INC_COUNT(read_count);
	
	locals_info[local] |= (1 << local_type) | LOCAL_SET_COUNTS(read_count, write_count) | local_modified;
	if (local_type == LOCAL_LONG || local_type == LOCAL_DOUBLE) {
	  locals_info[local+1] |= (1 << local_type) | LOCAL_SET_COUNTS(read_count, write_count) | local_modified;
	}
      }
      bci += BCI_LEN(bytecodeinfo);
      stackdepth += BCI_PUSH(bytecodeinfo) - BCI_POP(bytecodeinfo);
      JASSERT(stackdepth <= (unsigned)jinfo->method->max_stack(), "stack over/under flow?");
      continue;
    }

    switch (opcode) {

      case opc_goto:
	bci += GET_JAVA_S2(code_base+bci+1);
	break;
      case opc_goto_w:
	bci += GET_JAVA_U4(code_base+bci+1);
	break;

      case opc_ifeq:
      case opc_ifne:
      case opc_iflt:
      case opc_ifge:
      case opc_ifgt:
      case opc_ifle:
      case opc_ifnull:
      case opc_ifnonnull:
	stackdepth -= 1;
	Thumb2_pass2(jinfo, stackdepth, bci + GET_JAVA_S2(code_base+bci+1));
	check_zombie = 1;
	bci += 3;
	break;

      case opc_if_icmpeq:
      case opc_if_icmpne:
      case opc_if_icmplt:
      case opc_if_icmpge:
      case opc_if_icmpgt:
      case opc_if_icmple:
      case opc_if_acmpeq:
      case opc_if_acmpne:
	stackdepth -= 2;
	Thumb2_pass2(jinfo, stackdepth, bci + GET_JAVA_S2(code_base+bci+1));
	check_zombie = 1;
	bci += 3;
	break;

      case opc_jsr:
	Thumb2_pass2(jinfo, stackdepth+1, bci + GET_JAVA_S2(code_base+bci+1));
	bci += 3;
	stackdepth = 0;
	break;
      case opc_jsr_w:
	Thumb2_pass2(jinfo, stackdepth+1, bci + GET_JAVA_U4(code_base+bci+1));
	bci += 5;
	break;

      case opc_ireturn:
      case opc_lreturn:
      case opc_freturn:
      case opc_dreturn:
      case opc_areturn:
      case opc_return:
      case opc_return_register_finalizer:
      case opc_ret:
      case opc_athrow:
	// The test for BC_VISITED_P2 above will break out of the loop!!!
	break;

      case opc_tableswitch: {
	int low, high;
	unsigned w;
	unsigned *table;
	unsigned nbci;
	int def;

	stackdepth -= 1;
	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 8);
	low = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 12);
	high = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 4);
	def = (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 16);

	while (low <= high) {
	  int off;
	  w = *table++;
	  off = (int)BYTESEX_REVERSE(w);
	  Thumb2_pass2(jinfo, stackdepth, bci + off);
	  low++;
	}

	check_zombie = 1;
	bci += def;
	break;
      }

      case opc_lookupswitch: {
	unsigned w;
	unsigned nbci;
	int def;
	int npairs;	// The Java spec says signed but must be >= 0??
	unsigned *table;

	stackdepth -= 1;
	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 4);
	def = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 8);
	npairs = (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 16);

	for (int i = 0; i < npairs; i++) {
	  int off;
	  w = *table;
	  table += 2;
	  off = (int)BYTESEX_REVERSE(w);
	  Thumb2_pass2(jinfo, stackdepth, bci + off);
	}

	check_zombie = 1;
	bci += def;
	break;
      }

      case opc_getstatic:
      case opc_putstatic:
      case opc_getfield:
      case opc_putfield: {
	int index = GET_JAVA_U2(code_base+bci+1);
	constantPoolOop pool = jinfo->method->constants();
	symbolOop sig = pool->signature_ref_at(index);
	jbyte *base = sig->base();
	jbyte c = *base;
	int stackchange;

	opcode = code_base[bci];
	if (opcode == opc_getfield || opcode == opc_putfield)
	  stackdepth -= 1;
	stackchange = 1;
	if (c == 'J' || c == 'D') stackchange = 2;
	if (opcode == opc_getfield || opcode == opc_getstatic)
	  stackdepth += stackchange;
	else
	  stackdepth -= stackchange;
	bci += 3;
	break;
      }

      case opc_invokeresolved:
      case opc_invokespecialresolved:
      case opc_invokestaticresolved:
      case opc_invokevfinal:
      case opc_invokeinterface:
      case opc_invokevirtual:
      case opc_invokespecial:
      case opc_invokestatic: {
	int index = GET_JAVA_U2(code_base+bci+1);
	constantPoolOop pool = jinfo->method->constants();
	//symbolOop name = pool->name_ref_at(index);
	symbolOop sig = pool->signature_ref_at(index);
	jbyte *base = sig->base();

	//tty->print("%d: %s: %s\n", opcode, name->as_C_string(), sig->as_C_string());
	stackdepth += method_stackchange(base);
	opcode = code_base[bci];
	bci += 3;
	if (opcode == opc_invokeinterface) bci += 2;
	if (opcode != opc_invokestatic && opcode != opc_invokestaticresolved)
	  stackdepth -= 1;
	break;
      }

      case opc_multianewarray:
	stackdepth = (stackdepth - code_base[bci+3]) + 1;
	bci += 4;
	break;

      case opc_wide:
	opcode = code_base[bci+1];
	if (opcode == opc_iinc) {
	  bci += 6;
	} else {
	  bci += 4;
	  if (opcode == opc_iload ||
	  	opcode == opc_fload || opcode == opc_aload)
	    stackdepth += 1;
	  else if (opcode == opc_lload || opcode == opc_dload)
	    stackdepth += 2;
	  else if (opcode == opc_istore ||
	  	opcode == opc_fstore || opcode == opc_astore)
	    stackdepth -= 1;
	  else if (opcode == opc_lstore || opcode == opc_dstore)
	    stackdepth -= 2;
	  else if (opcode != opc_ret)
	    fatal1("Undefined wide opcode %d\n", opcode);
	}
	break;

      default:
	opcode = code_base[bci];
	fatal1("Undefined opcode %d\n", opcode);
	break;
    }
  }
}

//-------------------------------------------------------------------------------------

#define Thumb2		1
#define ThumbEE		0

#define	DA	0
#define	IA	1
#define DB	2
#define IB	3

#define	PUSH_ED	0
#define PUSH_EA	1
#define	PUSH_FD	2
#define	PUSH_FA	3

#define	POP_FA	0
#define	POP_FD	1
#define	POP_EA	2
#define	POP_ED	3

#define ROR(imm, sh) (((imm) >> (sh)) | ((imm) << (32 - (sh))))
#define ROL(imm, sh) (((imm) << (sh)) | ((imm) >> (32 - (sh))))

#define abs(i) ((i) < 0 ? -(i) : (i))
#define U(i) ((i) < 0 ? 0 : 1)

#define LS_STR		0
#define	LS_STRB		1
#define	LS_STRH		2
#define LS_LDRSB	3
#define	LS_LDR		4
#define LS_LDRB		5
#define	LS_LDRH		6
#define LS_LDRSH	7

#define LS_IS_LDR(op)	((op) >= LS_LDRSB)
#define LS_IS_WORD(op)	(((op) & 3) == LS_STR)
#define LS_IS_BYTE(op)	(((op) & 3) == LS_STRB || (op) == LS_LDRSB)
#define LS_IS_HW(op)	(((op) & 3) == LS_STRH || (op) == LS_LDRSH)

static const unsigned t_ls_ops[16] = {
	0x5000,		0xf8400000,
	0x5400,		0xf8000000,
	0x5200,		0xf8200000,
	0x5600,		0xf9100000,
	0x5800,		0xf8500000,
	0x5c00,		0xf8100000,
	0x5a00,		0xf8300000,
	0x5e00,		0xf9300000,
};

#define DP_ADC	0
#define DP_ADD	1
#define DP_AND	2
#define DP_ASR	3
#define DP_BIC	4
#define DP_CMN	5
#define DP_CMP	6
#define DP_EOR	7
#define DP_LSL	8
#define DP_LSR	9
#define DP_MOV	10
#define DP_MVN	11
#define DP_ORN	12
#define DP_ORR	13
#define DP_ROR	14
#define DP_RSB	15
#define DP_SBC	16
#define DP_SUB	17
#define DP_TEQ	18
#define DP_TST	19
#define DP_MUL	20

static const unsigned n_ops[] = {
	DP_SBC,		// ADC	x, y == SBC x, ~y
	DP_SUB,		// ADD	x, y == SUB x, -y
	DP_BIC,		// AND	x, y == BIX x, ~y
	(unsigned)-1,	// ASR
	DP_AND,		// BIC	x, y == AND x, ~y
	DP_CMP,		// CMN	x, y == CMP x, -y
	DP_CMN,		// CMP	x, y == CMN x, -y
	(unsigned)-1,	// EOR
	(unsigned)-1,	// LSL
	(unsigned)-1,	// LSR
	DP_MVN,		// MOV	x, y == MVN x, ~y
	DP_MOV,		// MVN	x, y == MOV x, ~y
	DP_ORR,		// ORN	x, y == ORR x, ~y
	DP_ORN,		// ORR	x, y == ORN x, ~y
	(unsigned)-1,	// ROR
	(unsigned)-1,	// RSB
	DP_ADC,		// SBC	x, y == ADC x, ~y
	DP_ADD,		// ADD	x, y == SUB x, -y
	(unsigned)-1,	// TEQ
	(unsigned)-1,	// TST
	(unsigned)-1,	// MUL
};

#define N_OP(op)	n_ops[(op)]

static const unsigned t_dop_ops[] = {
//	Rd, Rm, #N	Rd, Rn, Rm
	0xf1400000,	0xeb400000,	// ADC
	0xf1000000,	0xeb000000,	// ADD
	0xf0000000,	0xea000000,	// AND
	0xea4f0020,	0xfa40f000,	// ASR
	0xf0200000,	0xea200000,	// BIC
	0xf1100f00,	0xeb100f00,	// CMN
	0xf1b00f00,	0xebb00f00,	// CMP
	0xf0800000,	0xea800000,	// EOR
	0xea4f0000,	0xfa00f000,	// LSL
	0xea4f0010,	0xfa20f000,	// LSR
	0xf04f0000,	0xea4f0000,	// MOV
	0xf06f0000,	0xea6f0000,	// MVN
	0xf0600000,	0xea600000,	// ORN
	0xf0400000,	0xea400000,	// ORR
	0xea4f0030,	0xfa6f0000,	// ROR
	0xf1c00000,	0xebc00000,	// RSB
	0xf1600000,	0xeb600000,	// SBC
	0xf1a00000,	0xeba00000,	// SUB
	0xf0900f00,	0xea900f00,	// TEQ
	0xf0100f00,	0xea100f00,	// TST
	(unsigned)-1,	0xfb00f000,	// MUL
};

#define DP_IMM(op)	t_dop_ops[(op)*2]
#define DP_REG(op)	t_dop_ops[(op)*2+1]

#define VP_ADD	0
#define VP_SUB	1
#define VP_MUL	2
#define VP_DIV	3

static const unsigned t_vop_ops[] = {
	0xee300a00,			// VADD
	0xee300a40,			// VSUB
	0xee200a00,			// VMUL
	0xee800a00,			// VDIV
};

#define VP_REG(op)	t_vop_ops[op]

#define T1_LS_OP(op)	t_ls_ops[(op)*2]
#define T2_LS_OP(op)	t_ls_ops[(op)*2+1]

#define SHIFT_LSL	0
#define SHIFT_LSR	1
#define SHIFT_ASR	2
#define SHIFT_ROR	3
#define SHIFT_RRX	3

//------------------------------------------------------------------------------------

#define TBIT 1

#define E_STR_IMM6(src, imm6)		(0xce00 | ((imm6)<<3) | (src))
#define E_LDR_IMM6(dst, imm6)		(0xcc00 | ((imm6)<<3) | (dst))
#define E_LDR_IMM5(dst, imm5)		(0xcb00 | ((imm5)<<3) | (dst))
#define E_LDR_IMM3(dst, base, imm3)	(0xc800 | ((imm3)<<6) | ((base) << 3) | (dst))

#define T_MOV_IMM8(r, imm8)		(0x2000 | ((r)<<8) | (imm8))
#define T_MOV_BYTELANE(r, typ, b)	(0xf04f0000 | ((typ) << 12) | ((r) << 8) | (b))
#define T_MOV_ROT_IMM(r, ror, imm)	\
		(0xf04f0000 | (((ror) & 0x10) << (26-4)) | (((ror) & 0xe) << (12-1)) |	\
		(((ror) & 1) << 7) | ((r) << 8) | ((imm) & 0x7f))
#define T_MOVW_IMM16(r, imm)		\
		(0xf2400000 | (((imm) & 0xf000) << (16-12)) | (((imm) & 0x800) << (26-11)) | \
		(((imm) & 0x700) << (12-8)) | ((imm) & 0xff) | ((r) << 8))
#define T_MOVT_IMM16(r, imm)		\
		(0xf2c00000 | (((imm) & 0xf000) << (16-12)) | (((imm) & 0x800) << (26-11)) | \
		(((imm) & 0x700) << (12-8)) | ((imm) & 0xff) | ((r) << 8))
#define T_MVN_BYTELANE(r, typ, b)	(0xf06f0000 | ((typ) << 12) | ((r) << 8) | (b))
#define T_MVN_ROT_IMM(r, ror, imm)	(0xf06f0000 | (((ror) & 0x10) << (26-4)) |	\
		(((ror) & 0xe) << (12-1)) | (((ror) & 1) << 7) | ((r) << 8) | ((imm) & 0x7f))

#define T_ORR_ROT_IMM(dst, src, ror, imm)	(0xf0400000 | (((ror) & 0x10) << (26-4)) | \
		(((ror) & 0xe) << (12-1)) | (((ror) & 1) << 7) | ((src) << 16) |	\
		((dst) << 8) | ((imm) & 0x7f))
#define T_ORN_ROT_IMM(dst, src, ror, imm)	(0xf0600000 | (((ror) & 0x10) << (26-4)) | \
		(((ror) & 0xe) << (12-1)) | (((ror) & 1) << 7) | ((src) << 16) |	\
		((dst) << 8) | ((imm) & 0x7f))

#define T_STR_IMM5(src, base, imm5)	(0x6000 | ((imm5) << 6) | ((base) << 3) | (src))
#define T_STR_SP_IMM8(src, imm8)	(0x9000 | ((src) << 8) | (imm8))
#define T_STR_IMM12(src, base, imm12)	(0xf8c00000 | ((src)<<12) | ((base)<<16) | (imm12))
#define T_STR_IMM8(src, base, imm8, pre, wb)	(0xf8400800 | ((src)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDR_IMM5(dst, base, imm5)	(0x6800 | ((imm5) << 6) | ((base) << 3) | (dst))
#define T_LDR_SP_IMM8(src, imm8)	(0x9800 | ((dst) << 8) | (imm8))
#define T_LDR_IMM12(dst, base, imm12)	(0xf8d00000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_LDR_IMM8(src, base, imm8, pre, wb)	(0xf8500800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_STRB_IMM5(src, base, imm5)	(0x7000 | ((imm5) << 6) | ((base) << 3) | (src))
#define T_STRB_IMM12(src, base, imm12)	(0xf8800000 | ((src)<<12) | ((base)<<16) | (imm12))
#define T_STRB_IMM8(src, base, imm8, pre, wb)	(0xf8000800 | ((src)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDRB_IMM5(dst, base, imm5)	(0x7800 | ((imm5) << 6) | ((base) << 3) | (dst))
#define T_LDRB_IMM12(dst, base, imm12)	(0xf8900000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_LDRB_IMM8(dst, base, imm8, pre, wb)	(0xf8100800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_STRH_IMM5(dst, base, imm5)	(0x8000 | ((imm5) << 6) | ((base) << 3) | (dst))
#define T_STRH_IMM12(dst, base, imm12)	(0xf8a00000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_STRH_IMM8(dst, base, imm8, pre, wb)	(0xf8200800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDRH_IMM5(dst, base, imm5)	(0x8800 | ((imm5) << 6) | ((base) << 3) | (dst))
#define T_LDRH_IMM12(dst, base, imm12)	(0xf8b00000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_LDRH_IMM8(dst, base, imm8, pre, wb)	(0xf8300800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDRSH_IMM12(dst, base, imm12)	(0xf9b00000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_LDRSH_IMM8(dst, base, imm8, pre, wb)	(0xf9300800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDRSB_IMM12(dst, base, imm12)	(0xf9900000 | ((dst)<<12) | ((base)<<16) | (imm12))
#define T_LDRSB_IMM8(dst, base, imm8, pre, wb)	(0xf9100800 | ((dst)<<12) | 		\
		((base)<<16) | ((pre)<<10) | (U(imm8)<<9) | ((wb)<<8) | abs(imm8))

#define T_LDRD_IMM(lo, hi, base, imm8, pre, wb)	(0xe8500000 | ((base)<<16) |		\
		((lo) << 12) | ((hi)<<8) | ((pre)<<24) | (U(imm8)<<23) | ((wb)<<21) | abs(imm8))
#define T_STRD_IMM(lo, hi, base, imm8, pre, wb)	(0xe8400000 | ((base)<<16) |		\
		((lo) << 12) | ((hi)<<8) | ((pre)<<24) | (U(imm8)<<23) | ((wb)<<21) | abs(imm8))

#define T_LDREX(dst, base, off) (0xe8500f00 | ((base) << 16) | ((dst) << 12) | ((off) >> 2))
#define T_STREX(dst, src, base, off) (0xe8400000 | ((base) << 16) | \
		((src) << 12) | ((dst) << 8) | ((off >> 2)))

#define T_STM8(base, regset)		(0xc000 | ((base) << 8) | (regset))
#define T_STM16(base, regset, st, wb)	(0xe8000000 | ((st) << 23) | ((wb) << 21) |	\
		((base) << 16) | (regset))

#define T_LDM8(base, regset)		(0xc800 | ((base) << 8) | (regset))
#define	T_LDM16(base, regset, st, wb)	(0xe8100000 | ((st) << 23) | ((wb) << 21) |	\
		((base) << 16) | (regset))
#define T_POP(regset)	(0xbc00 | (((regset & (1<<ARM_PC)) >> ARM_PC) << 8) | (regset & 0xff))
#define T_PUSH(regset)	(0xb400 | (((regset & (1<<ARM_LR)) >> ARM_LR) << 8) | (regset & 0xff))

#define	T1_LDR_STR_REG(op, xfer, base, off) 	((op) | ((off) << 6) | ((base) << 3) | (xfer))
#define T2_LDR_STR_REG(op, xfer, base, off, sh)	((op) | ((base) << 16) | ((xfer) << 12) | \
		((sh)<<4) | (off))

#define T_CHKA(size, idx)		(0xca00 | (((size) & 8) << (7-3)) | ((idx) << 3) | ((size) & 7))
#define T_HBL(handler)			(0xc300 | (handler))
#define T_ENTER_LEAVE(enter)		(0xf3bf8f0f | ((enter)<<4))

#define T1_ADD_IMM(dst, src, imm3)	(0x1c00 | ((imm3) << 6) | ((src) << 3) | (dst))
#define T2_ADD_IMM(r, imm8)		(0x3000 | ((r) << 8) | (imm8))
#define T3_ADD_BYTELANE(dst, src, typ, b) (0xf1000000 | ((src) << 16) | ((typ) << 12) | \
		((dst) << 8) | (b))
#define T3_ADD_ROT_IMM(dst, src, ror, imm) (0xf1000000 | ((src) << 16) | ((dst) << 8) | \
		(((ror) & 0x10) << (26-4)) | (((ror) & 0x0e) << (12-1)) | (((ror) & 1) << 7) | \
		((imm) & 0x7f))
#define T4_ADD_IMM(dst, src, imm)	(0xf2000000 | ((src) << 16) | ((dst) << 8) | \
		(((imm) & 0x800) << (26-11)) | (((imm) & 0x700) << (12-8)) | ((imm) & 0xff))

#define T1_SUB_IMM(dst, src, imm3)	(0x1e00 | ((imm3) << 6) | ((src) << 3) | (dst))
#define T2_SUB_IMM(r, imm8)		(0x3800 | ((r) << 8) | (imm8))
#define T3_SUB_BYTELANE(dst, src, typ, b) (0xf1a00000 | ((src) << 16) | ((typ) << 12) | \
		((dst) << 8) | (b))
#define T3_SUB_ROT_IMM(dst, src, ror, imm) (0xf1a00000 | ((src) << 16) | ((dst) << 8) | \
		(((ror) & 0x10) << (26-4)) | (((ror) & 0x0e) << (12-1)) | (((ror) & 1) << 7) | \
		((imm) & 0x7f))
#define T4_SUB_IMM(dst, src, imm)	(0xf2a00000 | ((src) << 16) | ((dst) << 8) | \
		(((imm) & 0x800) << (26-11)) | (((imm) & 0x700) << (12-8)) | ((imm) & 0xff))

#define T_DOP_BYTELANE(op, dst, src, typ, b)	((op) | ((dst) << 8) | ((src) << 16) | \
		((typ) << 12) | (b))
#define T_DOP_ROT_IMM(op, dst, src, ror, imm)	((op) | ((dst) << 8) | ((src) << 16) | \
		(((ror) & 0x10) << (26-4)) | (((ror) & 0x0e) << (12-1)) | (((ror) & 1) << 7) | \
		((imm) & 0x7f))
#define T_SHIFT_IMM(op, dst, src, imm)	((op) | ((dst) << 8) | (src) | \
		(((imm) & 3) << 6) | (((imm) & 0x1c) << (12-2)))
#define T_DOP_REG(op, dst, lho, rho, st, sh)	((op) | ((dst) << 8) | ((lho) << 16) | (rho) | \
		((st) << 4) | (((sh) & 0x1c) << (12-2)) | (((sh) & 3) << 6))
#define T3_ADD_BYTELANE(dst, src, typ, b) (0xf1000000 | ((src) << 16) | ((typ) << 12) | \
		((dst) << 8) | (b))

#define T_CMP_IMM(src, imm)		(0x2800 | ((src) << 8) | (imm))
#define T_CMP_REG(lho, rho)		(0x4280 | ((rho) << 3) | (lho))

#define T_NEG(dst, src)		(0x4240 | (dst) | ((src) << 3))
#define T_MVN(dst, src)		(0x43c0 | (dst) | ((src) << 3))
#define T_MOV(dst, src)		(0x4600 | (((dst) & 8) << (7-3)) | ((src) << 3) | ((dst) & 7))

#define T_VMOVS_TOARM(dst, src)	\
	(0xee100a10 | ((dst) << 12) | (((src) & 1) << 7) | (((src) & 0x1e)<<(16-1)))
#define T_VMOVS_TOVFP(dst, src) \
	(0xee000a10 | ((src) << 12) | (((dst) & 1) << 7) | (((dst) & 0x1e)<<(16-1)))

#define T_VMOVD_TOARM(dst_lo, dst_hi, src) \
  (0xec500b10 | ((dst_lo) << 12) | ((dst_hi) << 16) | (((src) & 0x10)<<(5-4)) | ((src) & 0x0f))
#define T_VMOVD_TOVFP(dst, src_lo, src_hi) \
  (0xec400b10 | ((src_lo) << 12) | ((src_hi) << 16) | (((dst) & 0x10)<<(5-4)) | ((dst) & 0x0f))

#define T_VOP_REG_S(op, dst, lho, rho)	((op) |				\
		(((dst) & 1) << 22) | (((dst) & 0x1e) << (12-1)) | 	\
		(((lho) & 1) << 7) | (((lho) & 0x1e) << (16-1))	 |	\
		(((rho) & 1) << 5) | (((rho) & 0x1e) >> 1))
#define T_VOP_REG_D(op, dst, lho, rho)	((op) |	(1 << 8) |		\
		(((dst) & 0x10) << (22-4)) | (((dst) & 0xf) << 12) | 	\
		(((lho) & 0x10) << (7-4)) | (((lho) & 0xf) << 16)   |	\
		(((rho) & 0x10) << (5-4)) | ((rho) & 0xf))

#define T_VCMP_S(lho, rho, e)		(0xeeb40a40 | ((e) << 7) |	\
		(((lho) & 1) << 22) | (((lho) & 0x1e) << (12-1)) |	\
		(((rho) & 1) << 5) | (((rho) & 0x1e) >>1))
#define T_VCMP_D(lho, rho, e)		(0xeeb40b40 | ((e) << 7) |	\
		(((lho) & 0x10) << (22-4)) | (((lho) & 0x0f) << 12) |	\
		(((rho) & 0x10) << (5-4)) | ((rho) & 0x0f))
#define T_VMRS(dst)	(0xeef10a10 | ((dst) << 12))

#define T_MLA(res, lho, rho, a) \
		(0xfb000000 | ((res) << 8) | ((lho) << 16) | (rho) | ((a) << 12))
#define T_UMULL(res_lo, res_hi, lho, rho) \
		(0xfba00000 | ((res_lo) << 12) | ((res_hi) << 8) | ((lho) << 16) | (rho))

#define T_BX(src)		(0x4700 | ((src) << 3))
#define T_TBH(base, idx)	(0xe8d0f010 | ((base) << 16) | (idx))

#define T_SXTB(dst, src)	(0xb240 | ((src) << 3) | (dst))
#define T_SXTH(dst, src)	(0xb200 | ((src) << 3) | (dst))
#define T2_SXTB(dst, src)	(0xfa4ff080 | ((dst) << 8) | (src))
#define T2_SXTH(dst, src)	(0xfa0ff080 | ((dst) << 8) | (src))
#define T_UXTH(dst, src)	(0xb280 | ((src) << 3) | (dst))
#define T2_UXTH(dst, src)	(0xfa1ff080 | ((dst) << 8) | (src))

int out_16(CodeBuf *codebuf, u32 s)
{
  if (codebuf->idx >= codebuf->limit)
	longjmp(compiler_error_env, COMPILER_RESULT_FATAL);
  codebuf->codebuf[codebuf->idx++] = s;
  return 0;
}

int out_16x2(CodeBuf *codebuf, u32 sx2)
{
  unsigned s1 = sx2 >> 16;
  unsigned s2 = sx2 & 0xffff;

  out_16(codebuf, s1);
  return out_16(codebuf, s2);
}

int out_32(CodeBuf *codebuf, u32 w)
{
  if (codebuf->idx + 2 > codebuf->limit)
	longjmp(compiler_error_env, COMPILER_RESULT_FATAL);
  *(u32 *)&(codebuf->codebuf[codebuf->idx]) = w;
  codebuf->idx += 2;
  return 0;
}

u32 out_pos(CodeBuf *codebuf)
{
  return (u32)&(codebuf->codebuf[codebuf->idx]);
}

u32 out_loc(CodeBuf *codebuf)
{
  return codebuf->idx * 2;
}

#define CODE_ALIGN 64
#define CODE_ALIGN_SIZE 64

u32 out_align(CodeBuf *codebuf, unsigned align)
{
  codebuf->idx += (((out_pos(codebuf) + (align-1)) & ~(align-1)) - out_pos(codebuf)) / sizeof(short);
  return out_pos(codebuf);
}

int thumb_single_shift(unsigned imm)
{
  unsigned lsl;

  if (!imm) return -1;
  lsl = 0;
  while (!(imm & 0x80000000)) {
    imm <<= 1;
    lsl++;
  }
  if (lsl >= 24) return -1;
  if ((imm & 0xff000000) == imm) return lsl+8;
  return -1;
}

int thumb_bytelane(u32 imm)
{
    unsigned b1 = imm & 0xff;
    unsigned b2 = (imm >> 8) & 0xff;
    unsigned b3 = (imm >> 16) & 0xff;
    unsigned b4 = imm >> 24;
    int mov_type = -1;

    if (b1 == b3 && b2 == 0 && b4 == 0) mov_type = 1;
    if (b1 == b2 && b1 == b3 && b1 == b4) mov_type = 3;
    if (b2 == b4 && b1 == 0 && b3 == 0) mov_type = 2;
    if (imm < 256) mov_type = 0;
    return mov_type;
}

int mov_imm(CodeBuf *codebuf, Reg r, u32 imm)
{
  int mov_type, rol;

  if (Thumb2) {
    if (r < ARM_R8 && imm < 256)
      return out_16(codebuf, T_MOV_IMM8(r, imm));
    mov_type = thumb_bytelane(imm);
    if (mov_type >= 0) {
      if (mov_type == 2) imm >>= 8;
      return out_16x2(codebuf, T_MOV_BYTELANE(r, mov_type, (imm & 0xff)));
    }
    mov_type = thumb_bytelane(~imm);
    if (mov_type >= 0) {
      imm = ~imm;
      if (mov_type == 2) imm >>= 8;
      return out_16x2(codebuf, T_MVN_BYTELANE(r, mov_type, (imm & 0xff)));
    }
    rol = thumb_single_shift(imm);
    if (rol >= 0)
      return out_16x2(codebuf, T_MOV_ROT_IMM(r, rol, ROL(imm, rol)));
    rol = thumb_single_shift(~imm);
    if (rol >= 0)
      return out_16x2(codebuf, T_MVN_ROT_IMM(r, rol, ROL(~imm, rol)));
    if ((imm & ~0xffff) == 0)
      return out_16x2(codebuf, T_MOVW_IMM16(r, imm & 0xffff));
    if (r < ARM_R8) {
      rol = thumb_single_shift(imm & ~0xff);
      if (rol >= 0) {
	out_16(codebuf, T_MOV_IMM8(r, imm & 0xff));
	return out_16x2(codebuf, T_ORR_ROT_IMM(r, r, rol, ROL(imm & ~0xff, rol)));
      }
    }
    out_16x2(codebuf, T_MOVW_IMM16(r, imm & 0xffff));
    return out_16x2(codebuf, T_MOVT_IMM16(r, imm >> 16));
  }
  J_Unimplemented();
}

int load_store_reg_no_wb(CodeBuf *codebuf, u32 op, Reg xfer, Reg base, Reg offset,
							  u32 shift, int pre)
{
  if (pre) {
    if (xfer < ARM_R8 && base < ARM_R8 && offset < ARM_R8) {
      if (ThumbEE) {
	if ((shift == 0 && LS_IS_BYTE(op)) || (shift == 1 && LS_IS_HW(op)) ||
							(shift == 2 && LS_IS_WORD(op)))
	  return out_16(codebuf, T1_LDR_STR_REG(T1_LS_OP(op), xfer, base, offset));
      } else if (shift == 0)
	return out_16(codebuf, T1_LDR_STR_REG(T1_LS_OP(op), xfer, base, offset));
    }
    if (shift < 4)
      return out_16x2(codebuf, T2_LDR_STR_REG(T2_LS_OP(op), xfer, base, offset, shift));
  }
  J_Unimplemented();
}

static int add_reg(CodeBuf *codebuf, u32 dst, u32 lho, u32 rho);

int load_store_reg(CodeBuf *codebuf, u32 op, Reg xfer, Reg base, Reg offset,
							  u32 shift, int pre, int wb)
{
  int rc = load_store_reg_no_wb(codebuf, op, xfer, base, offset, shift, pre);
  if (wb) {
    return add_reg(codebuf, base, base, offset);
  }
  return rc;
}

int str_reg(CodeBuf *codebuf, Reg src, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_STR, src, base, offset, shift, pre, wb);
}

int ldr_reg(CodeBuf *codebuf, Reg dst, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_LDR, dst, base, offset, shift, pre, wb);
}

int strb_reg(CodeBuf *codebuf, Reg src, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_STRB, src, base, offset, shift, pre, wb);
}

int ldrb_reg(CodeBuf *codebuf, Reg dst, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_LDRB, dst, base, offset, shift, pre, wb);
}

int strh_reg(CodeBuf *codebuf, Reg src, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_STRH, src, base, offset, shift, pre, wb);
}

int ldrh_reg(CodeBuf *codebuf, Reg dst, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_LDRH, dst, base, offset, shift, pre, wb);
}

int ldrsh_reg(CodeBuf *codebuf, Reg dst, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_LDRSH, dst, base, offset, shift, pre, wb);
}

int ldrsb_reg(CodeBuf *codebuf, Reg dst, Reg base, Reg offset, u32 shift, int pre, int wb)
{
  return load_store_reg(codebuf, LS_LDRSB, dst, base, offset, shift, pre, wb);
}

int ldrex_imm(CodeBuf *codebuf, Reg dst, Reg base, unsigned offset)
{
  if (Thumb2) {
    if ((offset & 3) == 0 && offset < 256 * 4) {
      return out_16x2(codebuf, T_LDREX(dst, base, offset));
    }
  }
  J_Unimplemented();
}

int strex_imm(CodeBuf *codebuf, Reg dst, Reg src, Reg base, unsigned offset)
{
  if (Thumb2) {
    if ((offset & 3) == 0 && offset < 256 * 4) {
      return out_16x2(codebuf, T_STREX(dst, src, base, offset));
    }
  }
  J_Unimplemented();
}

int str_imm(CodeBuf *codebuf, Reg src, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && src < ARM_R8 && uoff < 128 && (uoff & 3) == 0)
	return out_16(codebuf, T_STR_IMM5(src, base, uoff>>2));
      if (base == ARM_SP && src < ARM_R8 && uoff < 1024 && (uoff &3) ==0)
	return out_16(codebuf, T_STR_SP_IMM8(src, uoff>>2));
      if (ThumbEE && base == ARM_R9 && src < ARM_R8 && uoff < 256 && (uoff & 3) == 0)
	return out_16(codebuf, E_STR_IMM6(src, uoff>>2));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_STR_IMM12(src, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_STR_IMM8(src, base, offset, pre, wb));
    JASSERT(base != ARM_IP && src != ARM_IP, "src or base == IP in str_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return str_reg(codebuf, src, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int ldr_imm(CodeBuf *codebuf, Reg dst, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && dst < ARM_R8 && uoff < 128 && (uoff & 3) ==0)
	return out_16(codebuf, T_LDR_IMM5(dst, base, uoff>>2));
      if (base == ARM_SP && dst < ARM_R8 && uoff < 1024 & (uoff & 3) == 0)
	return out_16(codebuf, T_LDR_SP_IMM8(dst, uoff>>2));
      if (ThumbEE && base == ARM_R9 && dst < ARM_R8 && uoff < 256 && (uoff & 3) == 0)
	return out_16(codebuf, E_LDR_IMM6(dst, uoff>>2));
      if (ThumbEE && base == ARM_R10 && dst < ARM_R8 && uoff < 128 && (uoff & 3) == 0)
	return out_16(codebuf, E_LDR_IMM5(dst, uoff>>2));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_LDR_IMM12(dst, base, uoff));
    } else {
      if (ThumbEE && pre && !wb && offset <= 0 && offset > -32 && (uoff & 3) == 0 &&
							base < ARM_R8 && dst < ARM_R8)
	return out_16(codebuf, E_LDR_IMM3(dst, base, -offset >> 2));
      if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_LDR_IMM8(dst, base, offset, pre, wb));
    }
    JASSERT(base != ARM_IP, "base == IP in ldr_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return ldr_reg(codebuf, dst, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int strb_imm(CodeBuf *codebuf, Reg src, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && src < ARM_R8 && uoff < 32)
	return out_16(codebuf, T_STRB_IMM5(src, base, uoff));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_STRB_IMM12(src, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_STRB_IMM8(src, base, offset, pre, wb));
    JASSERT(base != ARM_IP && src != ARM_IP, "src or base == IP in str_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return strb_reg(codebuf, src, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int ldrb_imm(CodeBuf *codebuf, Reg dst, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && dst < ARM_R8 && uoff < 32)
	return out_16(codebuf, T_LDRB_IMM5(dst, base, uoff));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_LDRB_IMM12(dst, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_LDRB_IMM8(dst, base, offset, pre, wb));
    JASSERT(base != ARM_IP, "base == IP in ldr_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return ldrb_reg(codebuf, dst, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int strh_imm(CodeBuf *codebuf, Reg src, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && src < ARM_R8 && uoff < 64 && (uoff & 1) == 0)
	return out_16(codebuf, T_STRH_IMM5(src, base, uoff>>1));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_STRH_IMM12(src, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_STRH_IMM8(src, base, offset, pre, wb));
    JASSERT(base != ARM_IP && src != ARM_IP, "src or base == IP in str_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return strh_reg(codebuf, src, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int ldrh_imm(CodeBuf *codebuf, Reg dst, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (base < ARM_R8 && dst < ARM_R8 && uoff < 64 && (uoff & 1) == 0)
	return out_16(codebuf, T_LDRH_IMM5(dst, base, uoff>>1));
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_LDRH_IMM12(dst, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_LDRH_IMM8(dst, base, offset, pre, wb));
    JASSERT(base != ARM_IP, "base == IP in ldr_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return ldrh_reg(codebuf, dst, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int ldrsh_imm(CodeBuf *codebuf, Reg dst, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_LDRSH_IMM12(dst, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_LDRSH_IMM8(dst, base, offset, pre, wb));
    JASSERT(base != ARM_IP, "base == IP in ldr_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return ldrsh_reg(codebuf, dst, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int ldrsb_imm(CodeBuf *codebuf, Reg dst, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (pre && !wb && offset >= 0) {
      if (uoff < (1 << 12))
	return out_16x2(codebuf, T_LDRSB_IMM12(dst, base, uoff));
    } else if (offset < 256 && offset > -256)
	return out_16x2(codebuf, T_LDRSB_IMM8(dst, base, offset, pre, wb));
    JASSERT(base != ARM_IP, "base == IP in ldr_imm");
    mov_imm(codebuf, ARM_IP, offset);
    return ldrsb_reg(codebuf, dst, base, ARM_IP, 0, pre, wb);
  }
  J_Unimplemented();
}

int add_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm);

int ldrd_imm(CodeBuf *codebuf, Reg dst_lo, Reg dst_hi, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (offset < 256 * 4 && offset > -256 * 4 && (offset & 3) == 0)
      return out_16x2(codebuf, T_LDRD_IMM(dst_lo, dst_hi, base, offset>>2, pre, wb));
    if (pre && !wb) {
      add_imm(codebuf, ARM_IP, base, offset);
      return out_16x2(codebuf, T_LDRD_IMM(dst_lo, dst_hi, ARM_IP, 0, 1, 0));
    }
  }
  J_Unimplemented();
}

int strd_imm(CodeBuf *codebuf, Reg src_lo, Reg src_hi, Reg base, int offset, int pre, int wb)
{
  unsigned uoff;

  if (!pre && !wb) pre = 1, offset = 0;
  uoff = (unsigned)offset;
  if (Thumb2) {
    if (offset < 256 * 4 && offset > -256 * 4 && (offset & 3) == 0)
      return out_16x2(codebuf, T_STRD_IMM(src_lo, src_hi, base, offset>>2, pre, wb));
    if (pre && !wb) {
      add_imm(codebuf, ARM_IP, base, offset);
      return out_16x2(codebuf, T_STRD_IMM(src_lo, src_hi, ARM_IP, 0, 1, 0));
    }
  }
  J_Unimplemented();
}

int stm(CodeBuf *codebuf, u32 regset, u32 base, u32 st, u32 wb)
{
  JASSERT(regset != 0, "regset != 0 in stm");
  if (Thumb2) {
    if (!ThumbEE && base < ARM_R8 && (regset & ~0xff) == 0 && st == IA && wb)
      return out_16(codebuf, T_STM8(base, regset));
    if (base == ARM_SP) {
      if ((regset & ~0x40ff) == 0 && st == DB && wb)
	return out_16(codebuf, T_PUSH(regset));
    }
    if ((regset & -regset) == regset)
      return str_imm(codebuf, LOG2(regset), base, (st & 1) ? 4 : -4, (st & 2) >> 1, wb);
    if (st == PUSH_EA || st == PUSH_FD)
      return out_16x2(codebuf, T_STM16(base, regset, st, wb));
    return out_16x2(codebuf, T_STM16(base, regset, st, wb));
  }
  J_Unimplemented();
}

int ldm(CodeBuf *codebuf, u32 regset, u32 base, u32 st, u32 wb)
{
  JASSERT(regset != 0, "regset != 0 in stm");
  if (Thumb2) {
    if (!ThumbEE && base < ARM_R8 && (regset & ~0xff) == 0 && st == IA && wb)
      return out_16(codebuf, T_LDM8(base, regset));
    if (base == ARM_SP) {
      if ((regset & ~0x80ff) == 0 && st == IA && wb)
	return out_16(codebuf, T_POP(regset));
    }
    if ((regset & -regset) == regset)
      return ldr_imm(codebuf, LOG2(regset), base, (st & 1) ? 4 : -4, (st & 2) >> 1, wb);
    if (st == POP_EA || st == POP_FD)
      return out_16x2(codebuf, T_LDM16(base, regset, st, wb));
  }
  J_Unimplemented();
}

int dop_reg(CodeBuf *codebuf, u32 op, u32 dst, u32 lho, u32 rho, u32 sh_typ, u32 shift)
{
  unsigned s = 0;
  if (op != DP_MUL) s = 1 << 20;
//  JASSERT(dst != ARM_PC, "Terrible things happen if dst == PC && S bit set");
  return out_16x2(codebuf, T_DOP_REG(DP_REG(op)|s, dst, lho, rho, sh_typ, shift));
}

int dop_reg_preserve(CodeBuf *codebuf, u32 op, u32 dst, u32 lho, u32 rho, u32 sh_typ, u32 shift)
{
  return out_16x2(codebuf, T_DOP_REG(DP_REG(op), dst, lho, rho, sh_typ, shift));
}

int sxtb(CodeBuf *codebuf, u32 dst, u32 src)
{
  if (dst < ARM_R8 && src < ARM_R8)
    return out_16(codebuf, T_SXTB(dst, src));
  return out_16x2(codebuf, T2_SXTB(dst, src));
}

int sxth(CodeBuf *codebuf, u32 dst, u32 src)
{
  if (dst < ARM_R8 && src < ARM_R8)
    return out_16(codebuf, T_SXTH(dst, src));
  return out_16x2(codebuf, T2_SXTH(dst, src));
}

int uxth(CodeBuf *codebuf, u32 dst, u32 src)
{
  if (dst < ARM_R8 && src < ARM_R8)
    return out_16(codebuf, T_UXTH(dst, src));
  return out_16x2(codebuf, T2_UXTH(dst, src));
}

int mov_reg(CodeBuf *codebuf, u32 dst, u32 src)
{
  if (dst == src) return 0;
  if (dst == ARM_PC) return out_16(codebuf, T_BX(src));
  return out_16(codebuf, T_MOV(dst, src));
//  return dop_reg(codebuf, DP_MOV, dst, 0, src, SHIFT_LSL, 0);
}

int mvn_reg(CodeBuf *codebuf, u32 dst, u32 src)
{
  if (dst < ARM_R8 && src < ARM_R8)
    return out_16(codebuf, T_MVN(dst, src));
  return dop_reg(codebuf, DP_MVN, dst, 0, src, SHIFT_LSL, 0);
}

int vmov_reg_s_toVFP(CodeBuf *codebuf, u32 dst, u32 src)
{
  return out_16x2(codebuf, T_VMOVS_TOVFP(dst, src));
}

int vmov_reg_s_toARM(CodeBuf *codebuf, u32 dst, u32 src)
{
  return out_16x2(codebuf, T_VMOVS_TOARM(dst, src));
}

int vmov_reg_d_toVFP(CodeBuf *codebuf, u32 dst, u32 src_lo, u32 src_hi)
{
  return out_16x2(codebuf, T_VMOVD_TOVFP(dst, src_lo, src_hi));
}

int vmov_reg_d_toARM(CodeBuf *codebuf, u32 dst_lo, u32 dst_hi, u32 src)
{
  return out_16x2(codebuf, T_VMOVD_TOARM(dst_lo, dst_hi, src));
}

int vop_reg_s(CodeBuf *codebuf, u32 op, u32 dst, u32 lho, u32 rho)
{
  return out_16x2(codebuf, T_VOP_REG_S(VP_REG(op), dst, lho, rho));
}

int vop_reg_d(CodeBuf *codebuf, u32 op, u32 dst, u32 lho, u32 rho)
{
  return out_16x2(codebuf, T_VOP_REG_D(VP_REG(op), dst, lho, rho));
}

int vcmp_reg_s(CodeBuf *codebuf, u32 lho, u32 rho, unsigned e)
{
  return out_16x2(codebuf, T_VCMP_S(lho, rho, e));
}

int vcmp_reg_d(CodeBuf *codebuf, u32 lho, u32 rho, unsigned e)
{
  return out_16x2(codebuf, T_VCMP_D(lho, rho, e));
}

int vmrs(CodeBuf *codebuf, u32 dst)
{
  return out_16x2(codebuf, T_VMRS(dst));
}

int add_reg(CodeBuf *codebuf, u32 dst, u32 lho, u32 rho)
{
  return dop_reg(codebuf, DP_ADD, dst, lho, rho, SHIFT_LSL, 0);
}

int cmp_reg(CodeBuf *codebuf, Reg lho, Reg rho)
{
  if (lho < ARM_R8 && rho < ARM_R8)
    return out_16(codebuf, T_CMP_REG(lho, rho));
  return dop_reg(codebuf, DP_CMP, 0x0f, lho, rho, SHIFT_LSL, 0);
}

int add_reg_shift(CodeBuf *codebuf, u32 dst, u32 lho, u32 rho, u2 sh_typ, u32 shift)
{
  return dop_reg(codebuf, DP_ADD, dst, lho, rho, sh_typ, shift);
}

int add_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  int imm_type, rol;

  if (imm == 0) return mov_reg(codebuf, dst, src);
  if (Thumb2) {
    if (dst < ARM_R8 && src < ARM_R8) {
      if (imm < 8)
	return out_16(codebuf, T1_ADD_IMM(dst, src, imm));
      if (-imm < 8)
	return out_16(codebuf, T1_SUB_IMM(dst, src, -imm));
      if (src == dst) {
	if (imm < 256)
	  return out_16(codebuf, T2_ADD_IMM(src, imm));
	if (-imm < 256)
	  return out_16(codebuf, T2_SUB_IMM(src, -imm));
      }
    }
    imm_type = thumb_bytelane(imm);
    if (imm_type >= 0) {
      if (imm_type == 2) imm >>= 8;
      return out_16x2(codebuf, T3_ADD_BYTELANE(dst, src, imm_type, (imm & 0xff)));
    }
    imm_type = thumb_bytelane(-imm);
    if (imm_type >= 0) {
      imm = -imm;
      if (imm_type == 2) imm >>= 8;
      return out_16x2(codebuf, T3_SUB_BYTELANE(dst, src, imm_type, (imm & 0xff)));
    }
    rol = thumb_single_shift(imm);
    if (rol >= 0)
      return out_16x2(codebuf, T3_ADD_ROT_IMM(dst, src, rol, ROL(imm, rol)));
    rol = thumb_single_shift(-imm);
    if (rol >= 0)
      return out_16x2(codebuf, T3_SUB_ROT_IMM(dst, src, rol, ROL(-imm, rol)));
    if (imm < (1 << 12))
      return out_16x2(codebuf, T4_ADD_IMM(dst, src, imm));
    if (-imm < (1 << 12))
      return out_16x2(codebuf, T4_SUB_IMM(dst, src, -imm));
    mov_imm(codebuf, ARM_IP, imm);
    return add_reg(codebuf, dst, src, ARM_IP);
  }
  J_Unimplemented();
}

int sub_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return add_imm(codebuf, dst, src, -imm);
}

int dop_imm_s(CodeBuf *codebuf, u32 op, u32 dst, u32 src, u32 imm, unsigned s)
{
    int imm_type, rol;
    unsigned n_op, n_imm;

    JASSERT(op == DP_ADC || op == DP_ADD || op == DP_AND || op == DP_BIC || op == DP_CMN ||
		op == DP_CMP || op == DP_EOR || op == DP_MOV || op == DP_MVN ||
		op == DP_ORN || op == DP_ORR || op == DP_RSB || op == DP_SBC ||
		op == DP_SUB || op == DP_TEQ || op == DP_TST, "bad op");
    if (op == DP_CMP || op == DP_CMN || op == DP_TEQ || op == DP_TST) dst = 0x0f;
    if (op == DP_MOV || op == DP_MVN) src = 0x0f;
    imm_type = thumb_bytelane(imm);
    if (imm_type >= 0) {
      if (imm_type == 2) imm >>= 8;
      return out_16x2(codebuf, T_DOP_BYTELANE(DP_IMM(op)|s, dst, src, imm_type, (imm & 0xff)));
    }
    rol = thumb_single_shift(imm);
    if (rol >= 0)
      return out_16x2(codebuf, T_DOP_ROT_IMM(DP_IMM(op)|s, dst, src, rol, ROL(imm, rol)));
    n_op = N_OP(op);
    if (n_op != (unsigned)-1) {
      n_imm = ~imm;
      if (op == DP_ADD || op == DP_SUB || op == DP_CMP || op == DP_CMN) n_imm = -imm;
      imm_type = thumb_bytelane(n_imm);
      if (imm_type >= 0) {
	if (imm_type == 2) n_imm >>= 8;
	return out_16x2(codebuf, T_DOP_BYTELANE(DP_IMM(n_op)|s, dst, src, imm_type, (n_imm & 0xff)));
      }
      rol = thumb_single_shift(n_imm);
      if (rol >= 0)
	return out_16x2(codebuf, T_DOP_ROT_IMM(DP_IMM(n_op)|s, dst, src, rol, ROL(n_imm, rol)));
    }
    mov_imm(codebuf, ARM_IP, imm);
    return out_16x2(codebuf, T_DOP_REG(DP_REG(op)|s, dst, src, ARM_IP, SHIFT_LSL, 0));
}

int dop_imm(CodeBuf *codebuf, u32 op, u32 dst, u32 src, u32 imm)
{
    return dop_imm_s(codebuf, op, dst, src, imm, 1<<20);
}

int dop_imm_preserve(CodeBuf *codebuf, u32 op, u32 dst, u32 src, u32 imm)
{
    return dop_imm_s(codebuf, op, dst, src, imm, 0);
}

int shift_imm(CodeBuf *codebuf, u32 op, u32 dst, u32 src, u32 imm)
{
    imm &= 31;
    if (imm == 0)
      return mov_reg(codebuf, dst, src);
    else
      return out_16x2(codebuf, T_SHIFT_IMM(DP_IMM(op), dst, src, imm));
}

int rsb_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  if (dst < ARM_R8 && src < ARM_R8 && imm == 0)
    return out_16(codebuf, T_NEG(dst, src));
  return dop_imm(codebuf, DP_RSB, dst, src, imm);
}

int adc_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return dop_imm(codebuf, DP_ADC, dst, src, imm);
}

int asr_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return shift_imm(codebuf, DP_ASR, dst, src, imm);
}

int eor_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return dop_imm(codebuf, DP_EOR, dst, src, imm);
}

int and_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return dop_imm(codebuf, DP_AND, dst, src, imm);
}

int orr_imm(CodeBuf *codebuf, u32 dst, u32 src, u32 imm)
{
  return dop_imm(codebuf, DP_ORR, dst, src, imm);
}

int cmp_imm(CodeBuf *codebuf, Reg src, u32 imm)
{
  if (src <= ARM_R8 && imm < 256) return out_16(codebuf, T_CMP_IMM(src, imm));
  return dop_imm(codebuf, DP_CMP, 0x0f, src, imm);
}

int tst_imm(CodeBuf *codebuf, Reg src, u32 imm)
{
  return dop_imm(codebuf, DP_TST, 0x0f, src, imm);
}

int hbl(CodeBuf *codebuf, unsigned handler)
{
  mov_imm(codebuf, ARM_IP, 0);
  str_imm(codebuf, ARM_IP, ARM_IP, 0, 1, 0);
#if 0
  if ((Thumb2 && ThumbEE))
    return out_16(codebuf, T_HBL(handler));
  if (TESTING)
    return mov_imm(codebuf, ARM_R8, handler);
  J_Unimplemented();
#endif
}

#if 0
int enter_leave(CodeBuf *codebuf, unsigned enter)
{
  if ((Thumb2 && ThumbEE))
    return out_16x2(codebuf, T_ENTER_LEAVE(enter));
  J_Unimplemented();
}
#endif

int tbh(CodeBuf *codebuf, Reg base, Reg idx)
{
  out_16x2(codebuf, T_TBH(base, idx));
}

int umull(CodeBuf *codebuf, u32 res_lo, u32 res_hi, u32 lho, u32 rho)
{
  return out_16x2(codebuf, T_UMULL(res_lo, res_hi, lho, rho));
}

int mla(CodeBuf *codebuf, u32 res, u32 lho, u32 rho, u32 a)
{
  return out_16x2(codebuf, T_MLA(res, lho, rho, a));
}

#define COND_EQ 0
#define COND_NE 1
#define COND_LT	2
#define COND_GE 3
#define COND_GT 4
#define COND_LE 5
#define COND_CS 6
#define COND_CC 7
#define COND_MI 8
#define COND_PL 9

static unsigned conds[] = {
	0x0,
	0x1,
	0xb,
	0xa,
	0xc,
	0xd,
	0x2,
	0x3,
	0x4,
	0x5,
};

#define NEG_COND(cond)	((cond) ^ 1)

#define T_B(uoff)	(0xe000 | ((uoff) & 0x7ff))
#define T_BW(uoff)	(0xf0009000 | \
			  (((uoff) & (1<<23)) << (26-23)) | \
			  (((~(uoff) & (1<<22)) >> 22) ^ (((uoff) & (1<<23)) >> 23)) << 13 | \
			  (((~(uoff) & (1<<21)) >> 21) ^ (((uoff) & (1<<23)) >> 23)) << 11 | \
			  (((uoff) & 0x1ff800) << (16-11)) | \
			  ((uoff) & 0x7ff))
#define T_BL(uoff)	(0xf000d000 | \
			  (((uoff) & (1<<23)) << (26-23)) | \
			  (((~(uoff) & (1<<22)) >> 22) ^ (((uoff) & (1<<23)) >> 23)) << 13 | \
			  (((~(uoff) & (1<<21)) >> 21) ^ (((uoff) & (1<<23)) >> 23)) << 11 | \
			  (((uoff) & 0x1ff800) << (16-11)) | \
			  ((uoff) & 0x7ff))
#define T_BLX(uoff)	(0xf000c000 | \
			  (((uoff) & (1<<23)) << (26-23)) | \
			  (((~(uoff) & (1<<22)) >> 22) ^ (((uoff) & (1<<23)) >> 23)) << 13 | \
			  (((~(uoff) & (1<<21)) >> 21) ^ (((uoff) & (1<<23)) >> 23)) << 11 | \
			  (((uoff) & 0x1ff800) << (16-11)) | \
			  ((uoff) & 0x7ff))
#define T_BCC(cond, uoff) (0xd000 | (conds[cond] << 8) | ((uoff) & 0xff))
#define T_BCCW(cond, uoff) (0xf0008000 | \
			     (conds[cond] << 22) | \
			     (((uoff) & (1<<19)) << (26-19)) | \
			     (((uoff) & (1<<18)) >> (18-11)) | \
			     (((uoff) & (1<<17)) >> (17-13)) | \
			     (((uoff) & 0x1f800) << (16-11)) | \
			     ((uoff) & 0x7ff))
#define T_BLX_REG(r)	(0x4780 | ((r) << 3))
#define T_CBZ(r, uoff)	(0xb100 | (((uoff) & 0x1f) << 3) | (((uoff) & 0x20) << (8-5)) | ((r) & 7))
#define T_CBNZ(r, uoff)	(0xb900 | (((uoff) & 0x1f) << 3) | (((uoff) & 0x20) << (8-5)) | ((r) & 7))

#define T_IT(cond, mask) (0xbf00 | (conds[cond] << 4) | (mask))

#define IT_MASK_T	8

#define PATCH(loc)	do {						\
	  unsigned oldidx = codebuf->idx;				\
	  codebuf->idx = (loc) >> 1;					\

#define HCTAP								\
	  codebuf->idx = oldidx;					\
    	} while (0)

int forward_16(CodeBuf *codebuf)
{
  int loc = out_loc(codebuf);
  out_16(codebuf, T_UNDEFINED_16);
  return loc;
}

int forward_32(CodeBuf *codebuf)
{
  int loc = out_loc(codebuf);
  out_32(codebuf, T_UNDEFINED_32);
  return loc;
}

int it(CodeBuf *codebuf, unsigned cond, unsigned mask)
{
  return out_16(codebuf, T_IT(cond, mask));
}

void t2_bug_align(CodeBuf *codebuf)
{
  unsigned pc = (unsigned)&codebuf->codebuf[codebuf->idx];
  if ((pc & 0xffe) != 0xffe) return;
  mov_reg(codebuf, ARM_R0, ARM_R0);
}

void t2_bug_fix(CodeBuf *codebuf, int offset)
{
  unsigned pc = (unsigned)&codebuf->codebuf[codebuf->idx];
  if ((pc & 0xffe) != 0xffe) return;
  if (offset >= 0 || offset < -(4096+4)) return;
  mov_reg(codebuf, ARM_R0, ARM_R0);
}

int branch_uncond(CodeBuf *codebuf, unsigned dest)
{
  unsigned loc = (codebuf->idx * 2) + 4;
  int offset;
  unsigned uoff;

  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  if (offset >= -(1<<10) && offset < (1<<10)) {
    uoff = offset;
    return out_16(codebuf, T_B(uoff));
  }
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<23) && offset < (1<<23)) {
    uoff = offset;
    return out_16x2(codebuf, T_BW(uoff));
  }
  J_Unimplemented();
}

int branch_uncond_patch(CodeBuf *codebuf, unsigned loc, unsigned dest)
{
  int offset;
  unsigned uoff;
  unsigned oldidx;
  int rc;

  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<23) && offset < (1<<23)) {
    uoff = offset & ((1<<24)-1);
    rc = out_16x2(codebuf, T_BW(uoff));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int branch_narrow_patch(CodeBuf *codebuf, unsigned loc)
{
  int offset;
  unsigned uoff;
  unsigned oldidx;
  unsigned dest;
  int rc;

  dest = codebuf->idx * 2;
  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  if (offset >= -(1<<10) && offset < (1<<10)) {
    uoff = offset & ((1<<11)-1);
    rc = out_16(codebuf, T_B(uoff));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int branch(CodeBuf *codebuf, unsigned cond, unsigned dest)
{
  unsigned loc = (codebuf->idx * 2) + 4;
  int offset;
  unsigned uoff;

  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  if (offset >= -(1<<7) && offset < (1<<7)) {
    uoff = offset;
    return out_16(codebuf, T_BCC(cond, uoff));
  }
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<19) && offset < (1<<19)) {
    uoff = offset;
    return out_16x2(codebuf, T_BCCW(cond, uoff));
  }
  J_Unimplemented();
}

int bcc_patch(CodeBuf *codebuf, unsigned cond, unsigned loc)
{
  int offset;
  unsigned uoff;
  unsigned oldidx;
  unsigned dest;
  int rc;

  dest = codebuf->idx * 2;
  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest-loc;
  if (offset >= -(1<<7) && offset < (1<<7)) {
    uoff = offset;
    rc = out_16(codebuf, T_BCC(cond, uoff));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int bl(CodeBuf *codebuf, unsigned dest)
{
  unsigned loc = (unsigned)&codebuf->codebuf[codebuf->idx] + 4;
  int offset;
  unsigned uoff;

  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<23) && offset < (1<<23)) {
    uoff = offset;
    return out_16x2(codebuf, T_BL(uoff));
  }
  J_Unimplemented();
}

int blx(CodeBuf *codebuf, unsigned dest)
{
  unsigned loc = (unsigned)&codebuf->codebuf[codebuf->idx] + 4;
  int offset;
  unsigned uoff;

  JASSERT((dest & 3) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  loc &= ~1;
  offset = dest - loc;
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<23) && offset < (1<<23)) {
    uoff = offset;
    return out_16x2(codebuf, T_BLX(uoff));
  }
  J_Unimplemented();
}

int branch_patch(CodeBuf *codebuf, unsigned cond, unsigned loc, unsigned dest)
{
  int offset;
  unsigned uoff;
  unsigned oldidx;
  int rc;

  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest - loc;
  t2_bug_fix(codebuf, offset);
  if (offset >= -(1<<19) && offset < (1<<19)) {
    uoff = offset & ((1<<20)-1);
    rc = out_16x2(codebuf, T_BCCW(cond, uoff));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int blx_reg(CodeBuf *codebuf, Reg r)
{
  return out_16(codebuf, T_BLX_REG(r));
}

int cbz_patch(CodeBuf *codebuf, Reg r, unsigned loc)
{
  unsigned offset;
  unsigned oldidx;
  unsigned dest;
  int rc;

  dest = codebuf->idx * 2;
  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest-loc;
  if (r < ARM_R8 && offset < 64) {
    rc = out_16(codebuf, T_CBZ(r, offset));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int cbnz_patch(CodeBuf *codebuf, Reg r, unsigned loc)
{
  unsigned offset;
  unsigned oldidx;
  unsigned dest;
  int rc;

  dest = codebuf->idx * 2;
  oldidx = codebuf->idx;
  codebuf->idx = loc >> 1;
  loc += 4;
  JASSERT((dest & 1) == 0 && (loc & 1) == 0, "unaligned code");
  dest >>= 1;
  loc >>= 1;
  offset = dest-loc;
  if (r < ARM_R8 && offset < 64) {
    rc = out_16(codebuf, T_CBNZ(r, offset));
    codebuf->idx = oldidx;
    return rc;
  }
  J_Unimplemented();
}

int chka(CodeBuf *codebuf, u32 size, u32 idx)
{
  cmp_reg(codebuf, idx, size);
  it(codebuf, COND_CS, IT_MASK_T);
  bl(codebuf, handlers[H_ARRAYBOUND]);
}

//-----------------------------------------------------------------------------------

void Thumb2_Push_Multiple(CodeBuf *codebuf, Reg *regs, unsigned nregs)
{
  unsigned regset = 0;
  unsigned regmask;
  unsigned i;
  Reg r;

  JASSERT(nregs > 0, "nregs must be > 0");
  if (nregs == 1) {
    str_imm(codebuf, regs[0], Rstack, -4, 1, 1);
    return;
  }
  for (i = 0; i < nregs; i++) {
    r = regs[i];
    if (!IS_ARM_INT_REG(r)) J_Unimplemented();
    regmask = 1<<r;
    if (regset != 0 && regmask >= (regset & -regset)) {
      stm(codebuf, regset, Rstack, PUSH_FD, 1);
      regset = 0;
    }
    regset |= regmask;
  }
  stm(codebuf, regset, Rstack, PUSH_FD, 1);
}

void Thumb2_Pop_Multiple(CodeBuf *codebuf, Reg *regs, unsigned nregs)
{
  unsigned regset = 0;
  unsigned regmask;
  unsigned i;
  Reg r;

  JASSERT(nregs > 0, "nregs must be > 0");
  if (nregs == 1) {
    ldr_imm(codebuf, regs[0], Rstack, 4, 0, 1);
    return;
  }
  i = nregs;
  do {
    i--;
    r = regs[i];
    if (!IS_ARM_INT_REG(r)) J_Unimplemented();
    regmask = 1<<r;
    if (regmask <= (regset & -regset)) {
      ldm(codebuf, regset, Rstack, POP_FD, 1);
      regset = 0;
    }
    regset |= regmask;
  } while (i > 0);
  ldm(codebuf, regset, Rstack, POP_FD, 1);
}

#if 0
int load_multiple(CodeBuf *codebuf, Reg base, Reg *regs, u32 nregs, u32 st, u32 wb)
{
  unsigned regset = 0;
  unsigned regmask;
  unsigned pre = 0;
  int dir = 1;
  unsigned u;
  Reg r;

  if (st == IB || st == DB) pre = 4;
  if (st == DA || st == DB) dir = -4;
  JASSERT(nregs > 0, "nregs must be > 0");
  if (nregs == 1)
    return ldr_imm(codebuf, regs[0], base, dir, pre, wb);
  if (dir > 0) {
    u = 0;
    do {
      r = regs[u];
      regmask = 1<<r;
      if (regset != 0 && regmask >= regset) {
	if (!wb && base != ARM_IP) {
	  mov_reg(codebuf, ARM_IP, base);
	  base = ARM_IP;
	}
	ldm(codebuf, regset, base, st, 1);
	regset = 0;
      }
      regset |= regmask;
    } while (++u < nregs);
    ldm(codebuf, regset, base, st, wb);
  } else {
    u = nregs;
    do {
      u--;
      r = regs[u];
      regmask = 1<<r;
      if (regmask <= (regset & -regset)) {
	if (!wb && base != ARM_IP) {
	  mov_reg(codebuf, ARM_IP, base);
	  base = ARM_IP;
	}
	ldm(codebuf, regset, base, st, 1);
	regset = 0;
      }
      regset |= regmask;
    } while (u > 0);
    ldm(codebuf, regset, base, st, wb);
  }
}
#endif

int mov_multiple(CodeBuf *codebuf, Reg *dst, Reg *src, unsigned nregs)
{
  unsigned u, n, p;
  unsigned smask = 0;
  unsigned dmask = 0;
  unsigned free_mask, free_reg;

  for (u = 0, n = 0; u < nregs; u++) {
    JASSERT(dst[u] != ARM_IP, "mov_multiple cannot be used for ARM_IP");
    JASSERT(src[u] != ARM_IP, "mov_multiple cannot be used for ARM_IP");
    if (dst[u] != src[u]) {
      dst[n] = dst[u];
      src[n++] = src[u];
    }
  }
  while (n) {
    // Find a reg which is in the dst reg set but not the src reg set
    smask = 0;
    dmask = 0;
    for (u = 0; u < n; u++) {
      smask |= (1 << src[u]);
      dmask |= (1 << dst[u]);
    }
    free_mask = dmask & ~smask;
    if (!free_mask) {
      // No such reg => must use IP
      Reg r = dst[0];
      mov_reg(codebuf, ARM_IP, r);
      for (u = 0; u < n; u++) {
	if (src[u] == r) src[u] = ARM_IP;
      }
      smask ^= (1<<r) | (1<<ARM_IP);
      free_mask = dmask & ~smask;
      JASSERT(free_mask, "still no free reg after using ARM_IP?");
    }
    free_reg = LOG2(free_mask);
    for (u = 0, p = 0; u < n; u++) {
      if (dst[u] == free_reg) {
	mov_reg(codebuf, dst[u], src[u]);
      } else {
	dst[p] = dst[u];
	src[p++] = src[u];
      }
    }
    n--;
  }
  return 0;
}

#define TOS(jstack)	((jstack)->stack[(jstack)->depth-1])
#define TOSM1(jstack)	((jstack)->stack[(jstack)->depth-2])
#define TOSM2(jstack)	((jstack)->stack[(jstack)->depth-3])
#define TOSM3(jstack)	((jstack)->stack[(jstack)->depth-4])

#define POP(jstack)		((jstack)->stack[--(jstack)->depth])
#define PUSH(jstack, r)		((jstack)->stack[(jstack)->depth++] = (r))
#define SWAP(jstack) do { \
		      Reg r = (jstack)->stack[(jstack)->depth-1]; \
		      (jstack)->stack[(jstack)->depth-1] = (jstack)->stack[(jstack)->depth-2]; \
		      (jstack)->stack[(jstack)->depth-2] = r; \
		    } while (0)

#define JSTACK_REG(jstack)		jstack_reg(jstack)
#define JSTACK_PREFER(jstack, prefer)	jstack_prefer(jstack, prefer)

static const unsigned last_clear_bit[] = {
	3,	//	0000
	3,	//	0001
	3,	//	0010
	3,	//	0011
	3,	//	0100
	3,	//	0101
	3,	//	0110
	3,	//	0111
	2,	//	1000
	2,	//	1001
	2,	//	1010
	2,	//	1011
	1,	//	1100
	1,	//	1101
	0,	//	1110
	0,	//	1111
};

#define LAST_CLEAR_BIT(mask) last_clear_bit[mask]

unsigned jstack_reg(Thumb2_Stack *jstack)
{
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned mask = 0;
  unsigned r;
  unsigned i;

  for (i = 0; i < depth; i++) mask |= 1 << stack[i];
  mask &= (1 << STACK_REGS) - 1;
  JASSERT(mask != (1 << STACK_REGS) - 1, "No free reg in push");
  r = LAST_CLEAR_BIT(mask);
  return r;
}

unsigned jstack_prefer(Thumb2_Stack *jstack, Reg prefer)
{
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned mask = 0;
  unsigned r;
  unsigned i;

  for (i = 0; i < depth; i++) mask |= 1 << stack[i];
  mask &= (1 << STACK_REGS) - 1;
  if ((prefer & ~mask) & 0x0f) mask |= (~prefer & ((1 << STACK_REGS) - 1));
  JASSERT(mask != (1 << STACK_REGS) - 1, "No free reg in push");
  r = LAST_CLEAR_BIT(mask);
  return r;
}

void Thumb2_Fill(Thumb2_Info *jinfo, unsigned required)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned mask = 0;
  unsigned tofill;
  unsigned r, i;

  if (depth >= required) return;
  tofill = required - depth;
  for (i = depth; i > 0;) {
    i--;
    mask |= 1 << stack[i];
    stack[i+tofill] = stack[i];
  }
  mask &= (1 << STACK_REGS) - 1;
  for (i = 0; i < tofill; i++) {
    JASSERT(mask != (1 << STACK_REGS) - 1, "Fill failed!!!");
    r = LAST_CLEAR_BIT(mask);
    mask |= (1 << r);
    stack[i] = r;
  }
  jstack->depth = depth + tofill;
  Thumb2_Pop_Multiple(jinfo->codebuf, stack, tofill);
}

static const unsigned bitcount[] = {
	0,	// 0000
	1,	// 0001
	1,	// 0010
	2,	// 0011
	1,	// 0100
	2,	// 0101
	2,	// 0110
	3,	// 0111
	1,	// 1000
	2,	// 1001
	2,	// 1010
	3,	// 1011
	2,	// 1100
	3,	// 1101
	3,	// 1110
	4,	// 1111
};

#define BITCOUNT(mask) bitcount[mask]

// Thumb2_Spill:-
// 	required - ensure that at least this many registers are available
// 	exclude - bitmask, do not count these registers as available
//
// 	The no. of available regs (STACK_REGS) less the no. of registers in
// 	exclude must be >= the number required, otherwise this function loops!
//
// 	Typical usage is
//
// 	Thumb2_Spill(jinfo, 2, 0);	// get 2 free regs
// 	r_res_lo = PUSH(jinfo->jstack, JSTACK_REG(jinfo->jstack));
// 	r_res_hi = PUSH(jinfo->jstack, JSTACK_REG(jinfo->jstack));
//
//	Use the exclude mask when you do not want a subsequent call to
//	JSTACK_REG to return a particular register or registers. This can
//	be useful, for example, with long (64) bit operations. Eg. In the
//	following we use it to ensure that the hi inputs are not clobbered
//	by the lo result as part of the intermediate calculation.
//
//	Thumb2_Fill(jinfo, 4);
//	exclude = (1<<rho_hi)|(1<<lho_hi);
//	rho_lo = POP(jstack);
//	rho_hi = POP(jstack);
//	lho_lo = POP(jstack);
//	lho_hi = POP(jstack);
//	Thumb2_Spill(jinfo, 2, exclude);
//	res_hi = PUSH(jstack, JSTACK_PREFER(jstack, ~exclude));	// != rho_hi or lho_hi
//	res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~exclude));	// != rho_hi or lho_hi
//	dop_reg(jinfo->codebuf, DP_ADD, res_lo, lho_lo, rho_lo, SHIFT_LSL, 0); 
//	dop_reg(jinfo->codebuf, DP_ADC, res_hi, lho_hi, rho_hi, SHIFT_LSL, 0);
//	
void Thumb2_Spill(Thumb2_Info *jinfo, unsigned required, unsigned exclude)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned mask;
  unsigned i;
  unsigned tospill = 0;

  exclude &= (1 << STACK_REGS) - 1;
  if (depth <= (STACK_REGS - required) && exclude == 0) return;
  while (1) {
    mask = 0;
    for (i = tospill; i < depth; i++) mask |= 1 << stack[i];
    mask &= ((1 << STACK_REGS) - 1);
    mask |= exclude;
    if (STACK_REGS - BITCOUNT(mask) >= required) break;
    tospill++;
  }
  if (tospill == 0) return;
  Thumb2_Push_Multiple(jinfo->codebuf, stack, tospill);
  for (i = tospill; i < depth; i++)
    stack[i-tospill] = stack[i];
  jstack->depth = depth - tospill;
  JASSERT((int)jstack->depth >= 0, "Stack underflow");
}

// Thumb2_Tmp:-
// 	Allocate a temp reg for use in local code generation.
// 	exclude is a bit mask of regs not to use.
// 	A max of 2 regs can be guaranteed (ARM_IP & ARM_LR)
// 	If allocating 2 regs you must include the reg you got the
// 	first time in the exclude list. Otherwise you just get
// 	the same reg again.
Reg Thumb2_Tmp(Thumb2_Info *jinfo, unsigned exclude)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned mask;
  unsigned i;

  mask = 0;
  for (i = 0; i < depth; i++) mask |= 1 << stack[i];
  mask |= exclude;
  for (i = 0; i < STACK_REGS; i++)
    if ((mask & (1<<i)) == 0) return i;
  if ((mask & (1<<ARM_IP)) == 0) return ARM_IP;
  if ((mask & (1<<ARM_LR)) == 0) return ARM_LR;
  JASSERT(0, "failed to allocate a tmp reg");
}

void Thumb2_Flush(Thumb2_Info *jinfo)
{
  Thumb2_Stack *jstack = jinfo->jstack;

  if (jstack->depth > 0)
    Thumb2_Push_Multiple(jinfo->codebuf, jstack->stack, jstack->depth);
  jstack->depth = 0;
}

// Call this when we are about to corrupt a local
// The local may already be on the stack
// For example
// 	iload	0
// 	iconst	2
// 	istore	0
// 	istore	1
// Without this check the code generated would be (r4 is local 0, r5 is local 1)
// 	mov	r4, #2
//	mov	r5, r4
// With this check the code should be
// 	mov	r3, r4
// 	mov	r4, #2
// 	mov	r5, r3
// This is not ideal, but is better than the previous:-)
//
void Thumb2_Corrupt(Thumb2_Info *jinfo, unsigned r, unsigned ignore)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth = jstack->depth;
  unsigned r_new, mask;
  unsigned i;

  if (ignore >= depth) return;
//  JASSERT(depth >= ignore, "Cant ignore more than the whole stack!!");
  if (IS_SREG(r)) return;
  depth -= ignore;
  for (i = 0; i < depth; i++) {
    if (r == stack[i]) {
      Thumb2_Spill(jinfo, 1, 0);
      depth = jstack->depth - ignore;
      r_new = JSTACK_REG(jstack);
      mov_reg(jinfo->codebuf, r_new, r);
      for (i = 0; i < depth; i++) if (r == stack[i]) stack[i] = r_new;
      break;
    }
  }
}

unsigned Thumb2_ResultLocal(Thumb2_Info *jinfo, unsigned bci)
{
  unsigned opc = jinfo->code_base[bci];
  if (jinfo->bc_stackinfo[bci] & BC_BRANCH_TARGET) return 0;
  if (opc < opc_istore || opc > opc_astore_3) return 0;
  if (opc == opc_istore || opc == opc_fstore || opc == opc_astore)
    return jinfo->jregs->r_local[jinfo->code_base[bci+1]];
  if ((opc >= opc_istore_0 && opc <= opc_istore_3) ||
	(opc >= opc_fstore_0 && opc <= opc_fstore_3) ||
	(opc >= opc_astore_0 && opc <= opc_astore_3))
    return jinfo->jregs->r_local[(opc-opc_istore_0)&3];
  return 0;
}

static const unsigned char dOps[] = {
	DP_ADD, DP_ADC, VP_ADD, VP_ADD,
	DP_SUB, DP_SBC, VP_SUB, VP_SUB,
	DP_MUL, 0, VP_MUL, VP_MUL,
	0, 0, VP_DIV, VP_DIV,
	0, 0, 0, 0,
	0, 0, 0, 0,
	DP_LSL, 0,
	DP_ASR, 0,
	DP_LSR, 0,
	DP_AND, DP_AND, DP_ORR, DP_ORR, DP_EOR, DP_EOR,
};

unsigned Thumb2_Imm(Thumb2_Info *jinfo, unsigned imm, unsigned next_bci)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r;
  unsigned next_op;

  if (!(jinfo->bc_stackinfo[next_bci] & BC_BRANCH_TARGET)) {
    next_op = jinfo->code_base[next_bci];
    if (next_op > OPC_LAST_JAVA_OP) {
      if (Bytecodes::is_defined((Bytecodes::Code)next_op))
	next_op = (unsigned)Bytecodes::java_code((Bytecodes::Code)next_op);
    }
    switch (next_op) {
      case opc_istore:
      case opc_fstore:
      case opc_astore: {
	unsigned local = jinfo->code_base[next_bci+1];
	r = jinfo->jregs->r_local[local];
	if (r) {
	  Thumb2_Corrupt(jinfo, r, 0);
	  mov_imm(jinfo->codebuf, r, imm);
	  return 2;
	}
	break;
      }
      case opc_istore_0:
      case opc_istore_1:
      case opc_istore_2:
      case opc_istore_3:
      case opc_fstore_0:
      case opc_fstore_1:
      case opc_fstore_2:
      case opc_fstore_3:
      case opc_astore_0:
      case opc_astore_1:
      case opc_astore_2:
      case opc_astore_3: {
	unsigned local = (jinfo->code_base[next_bci]-opc_istore_0) & 3;
	r = jinfo->jregs->r_local[local];
	if (r) {
	  Thumb2_Corrupt(jinfo, r, 0);
	  mov_imm(jinfo->codebuf, r, imm);
	  return 1;
	}
	break;
      }
      case opc_iadd:
      case opc_isub:
      case opc_ishl:
      case opc_ishr:
      case opc_iushr:
      case opc_iand:
      case opc_ior:
      case opc_ixor: {
	unsigned len = 0;
	unsigned r_lho;

	Thumb2_Fill(jinfo, 1);
	r_lho = POP(jstack);

	r = Thumb2_ResultLocal(jinfo, next_bci+1);
	if (r) {
	  Thumb2_Corrupt(jinfo, r, 0);
	  len = Bytecodes::length_for((Bytecodes::Code)jinfo->code_base[next_bci+1]);
	} else {
	  Thumb2_Spill(jinfo, 1, 0);
	  r = JSTACK_REG(jstack);
	  PUSH(jstack, r);
	}
	if (next_op == opc_ishl || next_op == opc_ishr || next_op == opc_iushr)
	  shift_imm(jinfo->codebuf, dOps[next_op-opc_iadd], r, r_lho, imm);
	else
	  dop_imm(jinfo->codebuf, dOps[next_op-opc_iadd], r, r_lho, imm);
	return 1+len;
      }

      case opc_idiv: {
	unsigned len = 0;
	unsigned r_lho;
	unsigned abs_imm = abs((int)imm);

	if ((imm & -imm) == abs_imm) {
	  unsigned l2_imm = LOG2(abs_imm);
	  unsigned r_lho;

	  if (imm == 0) break;
	  if (imm == 1) return 1;

	  Thumb2_Fill(jinfo, 1);
	  r_lho = POP(jstack);

	  r = Thumb2_ResultLocal(jinfo, next_bci+1);
	  if (r) {
	    Thumb2_Corrupt(jinfo, r, 0);
	    len = Bytecodes::length_for((Bytecodes::Code)jinfo->code_base[next_bci+1]);
	  } else {
	    Thumb2_Spill(jinfo, 1, 0);
	    r = JSTACK_REG(jstack);
	    PUSH(jstack, r);
	  }

	  if (abs_imm != 1) {
	    unsigned r_tmp = r_lho;
	    if (abs_imm != 2) {
	      r_tmp = Thumb2_Tmp(jinfo, (1<<r_lho));
	      asr_imm(jinfo->codebuf, r_tmp, r_lho, 31);
	    }
	    add_reg_shift(jinfo->codebuf, r, r_lho, r_tmp, SHIFT_LSR, 32-l2_imm);
	    asr_imm(jinfo->codebuf, r, r, l2_imm);
	  }
	  if ((int)imm < 0)
	    rsb_imm(jinfo->codebuf, r, r, 0);
	  return 1+len;
	}
	break;
      }
    }
  }
  Thumb2_Spill(jinfo, 1, 0);
  r = JSTACK_REG(jstack);
  PUSH(jstack, r);
  mov_imm(jinfo->codebuf, r, imm);
  return 0;
}

void Thumb2_ImmX2(Thumb2_Info *jinfo, unsigned lo, unsigned hi)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi;

  Thumb2_Spill(jinfo, 2, 0);
  r_hi = PUSH(jstack, JSTACK_REG(jstack));
  r_lo = PUSH(jstack, JSTACK_REG(jstack));
  mov_imm(jinfo->codebuf, r_lo, lo);
  mov_imm(jinfo->codebuf, r_hi, hi);
}

#define LOCAL_OFFSET(local, stackdepth, nlocals) ((stackdepth)*4 + FRAME_SIZE + ((nlocals)-1-(local))*4)

void load_local(Thumb2_Info *jinfo, Reg r, unsigned local, unsigned stackdepth)
{
#ifdef USE_RLOCAL
  ldr_imm(jinfo->codebuf, r, Rlocals, -local * 4, 1, 0);
#else
  int nlocals = jinfo->method->max_locals();
  ldr_imm(jinfo->codebuf, r, Rstack, LOCAL_OFFSET(local, stackdepth, nlocals), 1, 0);
#endif
}

void store_local(Thumb2_Info *jinfo, Reg r, unsigned local, unsigned stackdepth)
{
#ifdef USE_RLOCAL
  str_imm(jinfo->codebuf, r, Rlocals, -local << 2, 1, 0);
#else
  int nlocals = jinfo->method->max_locals();
  str_imm(jinfo->codebuf, r, Rstack, LOCAL_OFFSET(local, stackdepth, nlocals), 1, 0);
#endif
}

void Thumb2_Load(Thumb2_Info *jinfo, int local, unsigned stackdepth)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r;

  r = jinfo->jregs->r_local[local];
  if (r) {
    PUSH(jstack, r);
  } else {
    int nlocals = jinfo->method->max_locals();

    Thumb2_Spill(jinfo, 1, 0);
    JASSERT(stackdepth >= jstack->depth, "negative stack offset?");
    stackdepth -= jstack->depth;
    if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
    r = JSTACK_REG(jstack);
    PUSH(jstack, r);
    load_local(jinfo, r, local, stackdepth);
  }
}

void Thumb2_LoadX2(Thumb2_Info *jinfo, int local, unsigned stackdepth)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi;
  int nlocals = jinfo->method->max_locals();

  r_hi = jinfo->jregs->r_local[local];
  if (r_hi) {
    r_lo = jinfo->jregs->r_local[local+1];
    if (r_lo) {
      PUSH(jstack, r_hi);
      PUSH(jstack, r_lo);
    } else {
      Thumb2_Spill(jinfo, 1, 0);
      stackdepth -= jstack->depth;
      if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
      PUSH(jstack, r_hi);
      r_lo = PUSH(jstack, JSTACK_REG(jstack));
      load_local(jinfo, r_lo, local+1, stackdepth);
    }
  } else {
    r_lo = jinfo->jregs->r_local[local+1];
    if (r_lo) {
      Thumb2_Spill(jinfo, 1, 0);
      stackdepth -= jstack->depth;
      if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
      r_hi = PUSH(jstack, JSTACK_REG(jstack));
      load_local(jinfo, r_hi, local, stackdepth);
      PUSH(jstack, r_lo);
    } else {
      Thumb2_Spill(jinfo, 2, 0);
      stackdepth -= jstack->depth;
      if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
      r_hi = PUSH(jstack, JSTACK_REG(jstack));
      r_lo = PUSH(jstack, JSTACK_REG(jstack));
      load_local(jinfo, r_hi, local, stackdepth);
      load_local(jinfo, r_lo, local+1, stackdepth);
    }
  }
}

void Thumb2_Store(Thumb2_Info *jinfo, int local, unsigned stackdepth)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r, r_local;
  int nlocals = jinfo->method->max_locals();

  Thumb2_Fill(jinfo, 1);
  stackdepth -= jstack->depth;
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  r = POP(jstack);
  r_local = jinfo->jregs->r_local[local];
  if (r_local) {
    Thumb2_Corrupt(jinfo, r_local, 0);
    mov_reg(jinfo->codebuf, r_local, r);
  } else {
    store_local(jinfo, r, local, stackdepth);
  }
}

void Thumb2_StoreX2(Thumb2_Info *jinfo, int local, unsigned stackdepth)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi;
  unsigned r_local_lo, r_local_hi;
  int nlocals = jinfo->method->max_locals();

  Thumb2_Fill(jinfo, 2);
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  r_lo = POP(jstack);
  r_hi = POP(jstack);
  stackdepth -= 2;

  r_local_hi = jinfo->jregs->r_local[local];
  if (r_local_hi) {
    Thumb2_Corrupt(jinfo, r_local_hi, 0);
    mov_reg(jinfo->codebuf, r_local_hi, r_hi);
  } else {
    store_local(jinfo, r_hi, local, stackdepth-jstack->depth);
  }

  r_local_lo = jinfo->jregs->r_local[local+1];
  if (r_local_lo) {
    Thumb2_Corrupt(jinfo, r_local_lo, 0);
    mov_reg(jinfo->codebuf, r_local_lo, r_lo);
  } else {
    store_local(jinfo, r_lo, local+1, stackdepth-jstack->depth);
  }
}

void Thumb2_Xaload(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_index, r_array, r_value;
  unsigned op = opc - (unsigned)opc_iaload;
  unsigned r_tmp;

  Thumb2_Fill(jinfo, 2);
  r_index = POP(jstack);
  r_array = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r_tmp = Thumb2_Tmp(jinfo, (1<<r_array)|(1<<r_index));
  r_value = JSTACK_REG(jstack);
  PUSH(jstack, r_value);
  ldr_imm(jinfo->codebuf, r_tmp, r_array, 8, 1, 0);
  chka(jinfo->codebuf, r_tmp, r_index);
  if (opc == opc_baload) {
    add_reg(jinfo->codebuf, r_tmp, r_array, r_index);
    ldrsb_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  } else if (opc == opc_caload) {
    add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 1);
    ldrh_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  } else if (opc == opc_saload) {
    add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 1);
    ldrsh_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  } else {
    add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 2);
    ldr_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  }
}

void Thumb2_X2aload(Thumb2_Info *jinfo)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_index, r_array, r_lo, r_hi;
  unsigned r_tmp;

  Thumb2_Fill(jinfo, 2);
  r_index = POP(jstack);
  r_array = POP(jstack);
  Thumb2_Spill(jinfo, 2, 0);
  r_tmp = Thumb2_Tmp(jinfo, (1<<r_array)|(1<<r_index));
  r_hi = PUSH(jstack, JSTACK_REG(jstack));
  r_lo = PUSH(jstack, JSTACK_REG(jstack));
  ldr_imm(jinfo->codebuf, r_tmp, r_array, 8, 1, 0);
  chka(jinfo->codebuf, r_tmp, r_index);
  add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 3);
  ldrd_imm(jinfo->codebuf, r_lo, r_hi, r_tmp, 16, 1, 0);
}

void Thumb2_Xastore(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_value, r_index, r_array;
  unsigned op = opc - (unsigned)opc_iastore;
  unsigned r_tmp;

  Thumb2_Fill(jinfo, 3);
  r_value = POP(jstack);
  r_index = POP(jstack);
  r_array = POP(jstack);
  r_tmp = Thumb2_Tmp(jinfo, (1<<r_array)|(1<<r_index)|(1<<r_value));
  ldr_imm(jinfo->codebuf, r_tmp, r_array, 8, 1, 0);
  chka(jinfo->codebuf, r_tmp, r_index);
  if (opc == opc_bastore) {
    add_reg(jinfo->codebuf, r_tmp, r_array, r_index);
    strb_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  } else if (opc == opc_castore || opc == opc_sastore) {
    add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 1);
    strh_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  } else {
    add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 2);
    str_imm(jinfo->codebuf, r_value, r_tmp, 12, 1, 0);
  }
}

void Thumb2_X2astore(Thumb2_Info *jinfo)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi, r_index, r_array;
  unsigned r_tmp;

  Thumb2_Fill(jinfo, 4);
  r_lo = POP(jstack);
  r_hi = POP(jstack);
  r_index = POP(jstack);
  r_array = POP(jstack);
  r_tmp = Thumb2_Tmp(jinfo, (1<<r_array)|(1<<r_index)|(1<<r_lo)|(1<<r_hi));
  ldr_imm(jinfo->codebuf, r_tmp, r_array, 8, 1, 0);
  chka(jinfo->codebuf, r_tmp, r_index);
  add_reg_shift(jinfo->codebuf, r_tmp, r_array, r_index, SHIFT_LSL, 3);
  strd_imm(jinfo->codebuf, r_lo, r_hi, r_tmp, 16, 1, 0);
}

void Thumb2_Pop(Thumb2_Info *jinfo, unsigned n)
{
  Thumb2_Stack *jstack = jinfo->jstack;

  while (n > 0 && jstack->depth > 0) {
    POP(jstack);
    n--;
  }
  if (n > 0) add_imm(jinfo->codebuf, Rstack, Rstack, n * 4);
}

void Thumb2_Dup(Thumb2_Info *jinfo, unsigned n)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth;
  unsigned i;

  Thumb2_Fill(jinfo, n+1);
  depth = jstack->depth;
  for (i = 0; i <= n; i++)
    stack[depth-i] = stack[depth-i-1];
  stack[depth-n-1] = stack[depth];
  jstack->depth = depth + 1;
}

void Thumb2_Dup2(Thumb2_Info *jinfo, unsigned n)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned *stack = jstack->stack;
  unsigned depth;
  unsigned i;

  Thumb2_Fill(jinfo, n+2);
  depth = jstack->depth;
  for (i = 0; i <= n+1; i++)
    stack[depth-i+1] = stack[depth-i-1];
  stack[depth-n-1] = stack[depth+1];
  stack[depth-n-2] = stack[depth];
  jstack->depth = depth + 2;
}

void Thumb2_Swap(Thumb2_Info *jinfo)
{
  Thumb2_Stack *jstack = jinfo->jstack;

  Thumb2_Fill(jinfo, 2);
  SWAP(jstack);
}

void Thumb2_iOp(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lho, r_rho, r;

  Thumb2_Fill(jinfo, 2);
  r_rho = POP(jstack);
  r_lho = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r = JSTACK_REG(jstack);
  PUSH(jstack, r);
  dop_reg(jinfo->codebuf, dOps[opc-opc_iadd], r, r_lho, r_rho, 0, 0);
}

void Thumb2_iNeg(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_src, r;

  Thumb2_Fill(jinfo, 1);
  r_src = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r = JSTACK_REG(jstack);
  PUSH(jstack, r);
  rsb_imm(jinfo->codebuf, r, r_src, 0);
}

void Thumb2_lNeg(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi, r_res_lo, r_res_hi;
  unsigned r_tmp;

  Thumb2_Fill(jinfo, 2);
  r_lo = POP(jstack);
  r_hi = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r_res_hi = PUSH(jstack, JSTACK_REG(jstack));
  Thumb2_Spill(jinfo, 1, (1<<r_hi));
  r_res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~(1<<r_hi)));
  JASSERT(r_res_lo != r_res_hi, "oops");
  JASSERT(r_res_lo != r_hi, "r_res_lo != r_hi");
  rsb_imm(jinfo->codebuf, r_res_lo, r_lo, 0);
  r_tmp = Thumb2_Tmp(jinfo, (1<<r_hi)|(1<<r_res_lo));
  mov_imm(jinfo->codebuf, r_tmp, 0);
  dop_reg(jinfo->codebuf, DP_SBC, r_res_hi, r_tmp, r_hi, SHIFT_LSL, 0);
}

void Thumb2_fNeg(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r, r_result;

  Thumb2_Fill(jinfo, 1);
  r = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r_result = PUSH(jstack, JSTACK_REG(jstack));
  eor_imm(jinfo->codebuf, r_result, r, 0x80000000);
}

void Thumb2_dNeg(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned r_lo, r_hi, r_res_lo, r_res_hi;

  Thumb2_Fill(jinfo, 2);
  r_lo = POP(jstack);
  r_hi = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  r_res_hi = PUSH(jstack, JSTACK_REG(jstack));
  Thumb2_Spill(jinfo, 1, (1<<r_hi));
  r_res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~(1<<r_hi)));
  JASSERT(r_res_lo != r_res_hi, "oops");
  JASSERT(r_res_lo != r_hi, "r_res_lo != r_hi");
  mov_reg(jinfo->codebuf, r_res_lo, r_lo);
  eor_imm(jinfo->codebuf, r_res_hi, r_hi, 0x80000000);
}

void Thumb2_lOp(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned res_lo, res_hi;
  unsigned lho_lo, lho_hi;
  unsigned rho_lo, rho_hi;

  Thumb2_Fill(jinfo, 4);
  rho_lo = POP(jstack);
  rho_hi = POP(jstack);
  lho_lo = POP(jstack);
  lho_hi = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  res_hi = PUSH(jstack, JSTACK_REG(jstack));
  Thumb2_Spill(jinfo, 1, (1<<lho_hi)|(1<<rho_hi));
  res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_hi)|(1<<rho_hi))));
  JASSERT(res_lo != rho_hi && res_lo != lho_hi, "res_lo != rho_hi && res_lo != lho_hi");
  dop_reg(jinfo->codebuf, dOps[opc-opc_ladd], res_lo, lho_lo, rho_lo, SHIFT_LSL, 0);
  dop_reg(jinfo->codebuf, dOps[opc-opc_ladd+1], res_hi, lho_hi, rho_hi, SHIFT_LSL, 0);
}

void Thumb2_lmul(Thumb2_Info *jinfo)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned res_lo, res_hi;
  unsigned lho_lo, lho_hi;
  unsigned rho_lo, rho_hi;
  unsigned r_tmp_lo, r_tmp_hi;
  unsigned op_mask;

  Thumb2_Fill(jinfo, 4);
  rho_lo = POP(jstack);
  rho_hi = POP(jstack);
  lho_lo = POP(jstack);
  lho_hi = POP(jstack);
  op_mask = (1<<rho_lo)|(1<<rho_hi)|(1<<lho_lo)|(1<<lho_hi);
  Thumb2_Spill(jinfo, 2, 0);
  res_hi = PUSH(jstack, JSTACK_PREFER(jstack, ~op_mask));
  res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~op_mask));
  r_tmp_lo = res_lo;
  r_tmp_hi = res_hi;
  if (op_mask & (1<<r_tmp_lo)) r_tmp_lo = Thumb2_Tmp(jinfo, op_mask);
  if (op_mask & (1<<r_tmp_hi)) r_tmp_hi = Thumb2_Tmp(jinfo, op_mask|(1<<r_tmp_lo));
  umull(jinfo->codebuf, r_tmp_lo, r_tmp_hi, rho_lo, lho_lo);
  mla(jinfo->codebuf, r_tmp_hi, rho_lo, lho_hi, r_tmp_hi);
  mla(jinfo->codebuf, res_hi, rho_hi, lho_lo, r_tmp_hi);
  mov_reg(jinfo->codebuf, res_lo, r_tmp_lo);
}

void Thumb2_fOp(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned rho, lho, res;

  Thumb2_Fill(jinfo, 2);
  rho = POP(jstack);
  lho = POP(jstack);
  Thumb2_Spill(jinfo, 1, 0);
  res = PUSH(jstack, JSTACK_REG(jstack));
  vmov_reg_s_toVFP(jinfo->codebuf, VFP_S0, lho);
  vmov_reg_s_toVFP(jinfo->codebuf, VFP_S1, rho);
  vop_reg_s(jinfo->codebuf, dOps[opc-opc_iadd], VFP_S0, VFP_S0, VFP_S1);
  vmov_reg_s_toARM(jinfo->codebuf, res, VFP_S0);
}

void Thumb2_dOp(Thumb2_Info *jinfo, u32 opc)
{
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned rho_lo, rho_hi, lho_lo, lho_hi, res_lo, res_hi;

  Thumb2_Fill(jinfo, 4);
  rho_lo = POP(jstack);
  rho_hi = POP(jstack);
  lho_lo = POP(jstack);
  lho_hi = POP(jstack);
  Thumb2_Spill(jinfo, 2, 0);
  res_hi = PUSH(jstack, JSTACK_REG(jstack));
  res_lo = PUSH(jstack, JSTACK_REG(jstack));
  vmov_reg_d_toVFP(jinfo->codebuf, VFP_D0, lho_lo, lho_hi);
  vmov_reg_d_toVFP(jinfo->codebuf, VFP_D1, rho_lo, rho_hi);
  vop_reg_d(jinfo->codebuf, dOps[opc-opc_iadd], VFP_D0, VFP_D0, VFP_D1);
  vmov_reg_d_toARM(jinfo->codebuf, res_lo, res_hi, VFP_D0);
}

void Thumb2_Handler(Thumb2_Info *jinfo, unsigned handler, unsigned opcode, unsigned bci)
{
  mov_imm(jinfo->codebuf, ARM_R0, opcode);
  mov_imm(jinfo->codebuf, ARM_R1, bci);
  mov_imm(jinfo->codebuf, ARM_IP, 0);
  str_imm(jinfo->codebuf, ARM_IP, ARM_IP, 0, 1, 0);
//  hbl(jinfo->codebuf, handler);
}

void Thumb2_Debug(Thumb2_Info *jinfo, unsigned handler)
{
#if 0
  Thumb2_Flush(jinfo);
  bl(jinfo->codebuf, handlers[handler]);
#endif
}

void Thumb2_codegen(Thumb2_Info *jinfo, unsigned start);

int Thumb2_Branch(Thumb2_Info *jinfo, unsigned bci, unsigned cond)
{
    int offset = GET_JAVA_S2(jinfo->code_base + bci + 1);
    unsigned dest_taken = bci + offset;
    unsigned dest_not_taken = bci + 3;
    unsigned loc;

    if (jinfo->bc_stackinfo[dest_taken] & BC_COMPILED) {
      branch(jinfo->codebuf, cond, jinfo->bc_stackinfo[dest_taken] & ~BC_FLAGS_MASK);
      return dest_not_taken;
    }
    loc = forward_32(jinfo->codebuf);
    Thumb2_codegen(jinfo, dest_not_taken);
    JASSERT(jinfo->bc_stackinfo[dest_taken] & BC_COMPILED, "dest in branch not compiled!!!");
    branch_patch(jinfo->codebuf, cond, loc, jinfo->bc_stackinfo[dest_taken] & ~BC_FLAGS_MASK);
    return -1;
}

int Thumb2_Goto(Thumb2_Info *jinfo, unsigned bci, int offset, int len)
{
    unsigned dest_taken = bci + offset;
    unsigned dest_not_taken = bci + len;
    unsigned loc;

    if (jinfo->bc_stackinfo[dest_taken] & BC_COMPILED) {
      branch_uncond(jinfo->codebuf, jinfo->bc_stackinfo[dest_taken] & ~BC_FLAGS_MASK);
      return dest_not_taken;
    }
    loc = forward_32(jinfo->codebuf);
    Thumb2_codegen(jinfo, dest_not_taken);
    JASSERT(jinfo->bc_stackinfo[dest_taken] & BC_COMPILED, "dest in goto not compiled!!!");
    branch_uncond_patch(jinfo->codebuf, loc, jinfo->bc_stackinfo[dest_taken] & ~BC_FLAGS_MASK);
    return -1;
}

void Thumb2_Return(Thumb2_Info *jinfo, unsigned opcode)
{
  Reg r_lo, r;
  Thumb2_Stack *jstack = jinfo->jstack;

  if (0 /*jinfo->compiled_return*/) {
    unsigned bci = jinfo->compiled_return;

    JASSERT(jinfo->bc_stackinfo[bci] & BC_COMPILED, "return not compiled");
    JASSERT(jinfo->code_base[bci] == opcode, "type of return changed");
    branch_uncond(jinfo->codebuf, jinfo->bc_stackinfo[bci] & ~BC_FLAGS_MASK);
    return;
  }

  if (jinfo->method->is_synchronized()) {
    unsigned loc_success1, loc_success2, loc_failed, loc_retry, loc_exception;
    unsigned loc_illegal_monitor_state;
    Thumb2_Flush(jinfo);
//    Thumb2_save_locals(jinfo);
    // Free the monitor
    //
    // 		sub	r1, Ristate, #8
    // 		ldr	r2, [r1, #4]
    //		cbz	r2, throw_illegal_monitor_state
    //		ldr	r0, [r1, #0]
    //		mov	r3, #0
    //		str	r3, [r1, #4]
    //		cbz	r0, success
    //	retry:
    //		ldrex	r3, [r2, #0]
    //		cmp	r1, r3
    //		bne	failed
    //		strex	r3, r0, [r2, #0]
    //		cbz	r3, success
    //		b	retry
    //	failed:
    //		str	r2, [r1, #4]
    //		...
    //  success:
    //
    // JAZ_V1 == tmp2
    // JAZ_V2 == tmp1
    sub_imm(jinfo->codebuf, ARM_R1, Ristate, frame::interpreter_frame_monitor_size()*wordSize);
    ldr_imm(jinfo->codebuf, ARM_R2, ARM_R1, 4, 1, 0);
    loc_illegal_monitor_state = forward_16(jinfo->codebuf);
    ldr_imm(jinfo->codebuf, ARM_R0, ARM_R1, 0, 1, 0);
    mov_imm(jinfo->codebuf, ARM_R3, 0);
    str_imm(jinfo->codebuf, ARM_R3, ARM_R1, 4, 1, 0);
    loc_success1 = forward_16(jinfo->codebuf);
    loc_retry = out_loc(jinfo->codebuf);
    ldrex_imm(jinfo->codebuf, ARM_R3, ARM_R2, 0);
    cmp_reg(jinfo->codebuf, ARM_R1, ARM_R3);
    loc_failed = forward_16(jinfo->codebuf);
    strex_imm(jinfo->codebuf, ARM_R3, ARM_R0, ARM_R2, 0);
    loc_success2 = forward_16(jinfo->codebuf);
    branch_uncond(jinfo->codebuf, loc_retry);
    bcc_patch(jinfo->codebuf, COND_NE, loc_failed);
    cbz_patch(jinfo->codebuf, ARM_R2, loc_illegal_monitor_state);
    str_imm(jinfo->codebuf, ARM_R2, ARM_R1, 4, 1, 0);
    mov_imm(jinfo->codebuf, ARM_R0, 0+CONSTMETHOD_CODEOFFSET);
    bl(jinfo->codebuf, handlers[H_SYNCHRONIZED_EXIT]);
    loc_exception = forward_16(jinfo->codebuf);
    bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
    cbz_patch(jinfo->codebuf, ARM_R0, loc_exception);
    cbz_patch(jinfo->codebuf, ARM_R0, loc_success1);
    cbz_patch(jinfo->codebuf, ARM_R3, loc_success2);
  }

  if (opcode != opc_return) {
    if (opcode == opc_lreturn || opcode == opc_dreturn) {
      Thumb2_Fill(jinfo, 2);
      r_lo = POP(jstack);
      r = POP(jstack);
    } else {
      Thumb2_Fill(jinfo, 1);
      r = POP(jstack);
    }
  }

  mov_imm(jinfo->codebuf, ARM_LR, 0);
  str_imm(jinfo->codebuf, ARM_LR, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
  ldr_imm(jinfo->codebuf, Rstack, Rthread, THREAD_TOP_ZERO_FRAME, 1, 0);
  ldr_imm(jinfo->codebuf, ARM_LR, Rstack, 0, 1, 0);

  if (opcode == opc_return) {
    add_imm(jinfo->codebuf, Rstack, Rstack, jinfo->method->max_locals() * sizeof(int) + 4);
  } else {
    if (opcode == opc_lreturn || opcode == opc_dreturn) {
      str_imm(jinfo->codebuf, r, Rstack, jinfo->method->max_locals() * sizeof(int), 1, 0);
      str_imm(jinfo->codebuf, r_lo, Rstack, jinfo->method->max_locals() * sizeof(int)-4, 1, 1);
    } else
      str_imm(jinfo->codebuf, r, Rstack, jinfo->method->max_locals() * sizeof(int), 1, 1);
  }

//  sub_imm(jinfo->codebuf, Ristate, ARM_LR, ISTATE_NEXT_FRAME);
  str_imm(jinfo->codebuf, ARM_LR, Rthread, THREAD_TOP_ZERO_FRAME, 1, 0);
  str_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
  Thumb2_Debug(jinfo, H_DEBUG_METHODEXIT);
//  enter_leave(jinfo->codebuf, 0);
  ldm(jinfo->codebuf, C_REGSET + (1<<ARM_PC), ARM_SP, POP_FD, 1);
}

#if 0
void Thumb2_save_all_locals(Thumb2_Info *jinfo, unsigned stackdepth)
{
  int nlocals = jinfo->method->max_locals();
  int i;

  JASSERT(jinfo->jstack->depth == 0, "stack not empty");
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  for (i = 0; i < nlocals; i++) {
    Reg r = jinfo->jregs->r_local[i];
    if (r) {
	store_local(jinfo, r, i, stackdepth);
    }
  }
}
#endif

void Thumb2_save_locals(Thumb2_Info *jinfo, unsigned stackdepth)
{
  int nlocals = jinfo->method->max_locals();
  unsigned *locals_info = jinfo->locals_info;
  int i;

  JASSERT(jinfo->jstack->depth == 0, "stack not empty");
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  for (i = 0; i < nlocals; i++) {
    Reg r = jinfo->jregs->r_local[i];
    if (r) {
      if ((locals_info[i] & (1 << LOCAL_REF)) && (locals_info[i] & (1 << LOCAL_MODIFIED))) {
	store_local(jinfo, r, i, stackdepth);
      }
    }
  }
}

void Thumb2_restore_locals(Thumb2_Info *jinfo, unsigned stackdepth)
{
  int nlocals = jinfo->method->max_locals();
  unsigned *locals_info = jinfo->locals_info;
  int i;

  JASSERT(jinfo->jstack->depth == 0, "stack not empty");
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  for (i = 0; i < nlocals; i++) {
    Reg r = jinfo->jregs->r_local[i];
    if (r) {
      if (locals_info[i] & (1<<LOCAL_REF)) {
	load_local(jinfo, r, i, stackdepth);
      }
    }
  }
}

void Thumb2_invoke_save(Thumb2_Info *jinfo, unsigned stackdepth)
{
  int nlocals = jinfo->method->max_locals();
  unsigned *locals_info = jinfo->locals_info;
  int i;

  JASSERT(jinfo->jstack->depth == 0, "stack not empty");
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  for (i = 0; i < nlocals; i++) {
    Reg r = jinfo->jregs->r_local[i];
    if (r) {
      if (locals_info[i] & (1 << LOCAL_MODIFIED)) {
	store_local(jinfo, r, i, stackdepth);
      }
    }
  }
}

void Thumb2_invoke_restore(Thumb2_Info *jinfo, unsigned stackdepth)
{
  int nlocals = jinfo->method->max_locals();
  unsigned *locals_info = jinfo->locals_info;
  int i;

  JASSERT(jinfo->jstack->depth == 0, "stack not empty");
  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
  for (i = 0; i < nlocals; i++) {
    Reg r = jinfo->jregs->r_local[i];
    if (r) {
	load_local(jinfo, r, i, stackdepth);
    }
  }
}

void Thumb2_Exit(Thumb2_Info *jinfo, unsigned handler, unsigned bci, unsigned stackdepth)
{
    Thumb2_Flush(jinfo);
    Thumb2_invoke_save(jinfo, stackdepth);
    mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
    bl(jinfo->codebuf, handlers[handler]);
}

void Thumb2_Jsr(Thumb2_Info *jinfo, unsigned bci, unsigned stackdepth)
{
      Thumb2_Exit(jinfo, H_JSR, bci, stackdepth);
}

int Thumb2_Accessor(Thumb2_Info *jinfo)
{
  jubyte *code_base = jinfo->code_base;
  constantPoolCacheOop  cp = jinfo->method->constants()->cache();
  ConstantPoolCacheEntry* cache;
  int index = GET_NATIVE_U2(code_base+2);
  unsigned loc;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;

  JASSERT(code_base[0] == opc_aload_0 || code_base[0] == opc_iaccess_0, "not an aload_0 in accessor");
  JASSERT(code_base[4] == opc_ireturn || code_base[4] == opc_areturn, "not an ireturn in accessor");
  cache = cp->entry_at(index);
  if (!cache->is_resolved((Bytecodes::Code)opc_getfield)) return 0;

  TosState tos_type = cache->flag_state();
  int field_offset = cache->f2();

  // Slow entry point
  loc = forward_32(jinfo->codebuf);
  out_32(jinfo->codebuf, 0);
  out_32(jinfo->codebuf, 0);

  out_32(jinfo->codebuf, 0);	// pointer to osr table
  out_32(jinfo->codebuf, 0);	// Space for exception_table pointer
  out_32(jinfo->codebuf, 0);	// next compiled method

  out_32(jinfo->codebuf, 0);    // regusage
  out_32(jinfo->codebuf, 0);
  out_32(jinfo->codebuf, 0);

  // OSR entry point
  mov_reg(jinfo->codebuf, ARM_PC, ARM_R0);

  out_align(jinfo->codebuf, CODE_ALIGN);

  // fast entry point
  bc_stackinfo[0] = (bc_stackinfo[0] & BC_FLAGS_MASK) | (jinfo->codebuf->idx * 2) | BC_COMPILED;
  branch_uncond_patch(jinfo->codebuf, loc, jinfo->codebuf->idx * 2);
  ldr_imm(jinfo->codebuf, ARM_R1, ARM_R2, THREAD_JAVA_SP, 1, 0);
  ldr_imm(jinfo->codebuf, ARM_R0, ARM_R1, 0, 1, 0);
  if (tos_type == btos)
    ldrsb_imm(jinfo->codebuf, ARM_R0, ARM_R0, field_offset, 1, 0);
  else if (tos_type == ctos)
    ldrh_imm(jinfo->codebuf, ARM_R0, ARM_R0, field_offset, 1, 0);
  else if (tos_type == stos)
    ldrsh_imm(jinfo->codebuf, ARM_R0, ARM_R0, field_offset, 1, 0);
  else
    ldr_imm(jinfo->codebuf, ARM_R0, ARM_R0, field_offset, 1, 0);
  str_imm(jinfo->codebuf, ARM_R0, ARM_R1, 0, 1, 0);
  mov_reg(jinfo->codebuf, ARM_PC, ARM_LR);

  return 1;
}

void Thumb2_Enter(Thumb2_Info *jinfo)
{
  int parms = jinfo->method->size_of_parameters();
  int extra_locals = jinfo->method->max_locals() - parms;
  unsigned *locals_info = jinfo->locals_info;
  int i;

  // Slow entry point - callee save
  // R0 = method
  // R2 = thread
  stm(jinfo->codebuf, I_REGSET + (1<<ARM_LR), ARM_SP, PUSH_FD, 1);
  bl(jinfo->codebuf, out_pos(jinfo->codebuf) + CODE_ALIGN - 4);
  ldm(jinfo->codebuf, I_REGSET + (1<<ARM_PC), ARM_SP, POP_FD, 1);

  out_32(jinfo->codebuf, 0);	// Space for osr_table pointer
  out_32(jinfo->codebuf, 0);	// Space for exception_table pointer
  out_32(jinfo->codebuf, 0);	// Pointer to next method

  out_32(jinfo->codebuf, 0);    // regusage
  out_32(jinfo->codebuf, 0);
  out_32(jinfo->codebuf, 0);

  // OSR entry point == Slow entry + 16 - caller save
  // R0 = entry point within compiled method
  // R1 = locals - THUMB2_MAXLOCALS * 4
  // R2 = thread
  // R3 = locals - 31 * 4
  {
    int nlocals = jinfo->method->max_locals();

    for (i = 0; i < nlocals; i++) {
      Reg r = jinfo->jregs->r_local[i];
      if (r) {
	ldr_imm(jinfo->codebuf, r,
		(i < 32) ? ARM_R3 : ARM_R1,
		(i < 32) ? (31 - i) * 4 : (THUMB2_MAXLOCALS - i) * 4,
	  	1, 0);
      }
    }
    mov_reg(jinfo->codebuf, Rthread, ARM_R2);
    mov_reg(jinfo->codebuf, ARM_PC, ARM_R0);
  }

  out_align(jinfo->codebuf, CODE_ALIGN);

  // Fast entry point == Slow entry + 64 - caller save
  // R0 = method
  // R2 = thread
  stm(jinfo->codebuf, C_REGSET + (1<<ARM_LR), ARM_SP, PUSH_FD, 1);
//  enter_leave(jinfo->codebuf, 1);
  ldr_imm(jinfo->codebuf, Rstack, ARM_R2, THREAD_JAVA_SP, 1, 0);
  Thumb2_Debug(jinfo, H_DEBUG_METHODENTRY);
  {
    unsigned stacksize;

    stacksize = (extra_locals + jinfo->method->max_stack()) * sizeof(int);
    stacksize += FRAME_SIZE + STACK_SPARE;
    if (!jinfo->is_leaf || stacksize > LEAF_STACK_SIZE) {
      ldr_imm(jinfo->codebuf, ARM_R3, ARM_R2, THREAD_JAVA_STACK_BASE, 1, 0);
      sub_imm(jinfo->codebuf, ARM_R1, Rstack, stacksize + LEAF_STACK_SIZE);
      cmp_reg(jinfo->codebuf, ARM_R3, ARM_R1);
      it(jinfo->codebuf, COND_CS, IT_MASK_T);
      bl(jinfo->codebuf, handlers[H_STACK_OVERFLOW]);
    }
  }
  mov_imm(jinfo->codebuf, ARM_R1, 0);

  if (extra_locals > 0) {
    sub_imm(jinfo->codebuf, Rstack, Rstack, extra_locals * 4);

    for (i = 0; i < extra_locals; i++) {
      unsigned linfo = locals_info[parms+i];
      if (linfo & (1<< LOCAL_REF) || ((linfo >> LOCAL_INT) & 0x1f) == 0)
	str_imm(jinfo->codebuf, ARM_R1, Rstack, (extra_locals-1 - i) * 4, 1, 0);
    }
  }

  ldr_imm(jinfo->codebuf, ARM_IP, ARM_R0, METHOD_CONSTANTS, 1, 0);

  sub_imm(jinfo->codebuf, Ristate, Rstack, FRAME_SIZE);

  add_imm(jinfo->codebuf, Rlocals, Rstack, (jinfo->method->max_locals()-1) * sizeof(int));
  str_imm(jinfo->codebuf, Rlocals, Ristate, ISTATE_LOCALS, 1, 0);

  if (jinfo->method->is_synchronized()) {
    sub_imm(jinfo->codebuf, Rstack, Ristate, frame::interpreter_frame_monitor_size()*wordSize);
    if (jinfo->method->is_static()) {
      ldr_imm(jinfo->codebuf, ARM_R3, ARM_IP, CONSTANTPOOL_POOL_HOLDER, 1, 0);
      ldr_imm(jinfo->codebuf, JAZ_V1, ARM_R3, KLASS_PART+KLASS_JAVA_MIRROR, 1, 0);
    } else {
      ldr_imm(jinfo->codebuf, JAZ_V1, Rlocals, 0, 1, 0);
    }
    str_imm(jinfo->codebuf, JAZ_V1, Rstack, 4, 1, 0);
  } else
    mov_reg(jinfo->codebuf, Rstack, Ristate);

  str_imm(jinfo->codebuf, ARM_R1, Ristate, ISTATE_MSG, 1, 0);
  str_imm(jinfo->codebuf, ARM_R1, Ristate, ISTATE_OOP_TEMP, 1, 0);

  sub_imm(jinfo->codebuf, ARM_R3, Rstack, jinfo->method->max_stack() * sizeof(int));
  str_imm(jinfo->codebuf, ARM_R3, ARM_R2, THREAD_JAVA_SP, 1, 0);

  str_imm(jinfo->codebuf, Rstack, Ristate, ISTATE_STACK_BASE, 1, 0);

  sub_imm(jinfo->codebuf, ARM_R3, ARM_R3, 4);
  str_imm(jinfo->codebuf, ARM_R3, Ristate, ISTATE_STACK_LIMIT, 1, 0);

  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R2, THREAD_TOP_ZERO_FRAME, 1, 0);
  str_imm(jinfo->codebuf, ARM_R3, Ristate, ISTATE_NEXT_FRAME, 1, 0);

  mov_imm(jinfo->codebuf, ARM_R3, INTERPRETER_FRAME);
  str_imm(jinfo->codebuf, ARM_R3, Ristate, ISTATE_FRAME_TYPE, 1, 0);

  str_imm(jinfo->codebuf, Ristate, Ristate, ISTATE_MONITOR_BASE, 1, 0);

  add_imm(jinfo->codebuf, ARM_R3, Ristate, ISTATE_NEXT_FRAME);
  str_imm(jinfo->codebuf, ARM_R3, ARM_R2, THREAD_TOP_ZERO_FRAME, 1, 0);
  str_imm(jinfo->codebuf, ARM_R3, ARM_R2, THREAD_LAST_JAVA_SP, 1, 0);

  ldr_imm(jinfo->codebuf, ARM_R3, ARM_IP, CONSTANTPOOL_CACHE, 1, 0);
  str_imm(jinfo->codebuf, ARM_R3, Ristate, ISTATE_CONSTANTS, 1, 0);

  str_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_THREAD, 1, 0);
  str_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_METHOD, 1, 0);

  mov_reg(jinfo->codebuf, Rthread, ARM_R2);

  if (jinfo->method->is_synchronized()) {
    unsigned loc_retry, loc_failed, loc_success, loc_exception;

    // JAZ_V1 == monitor object
    //
    // Try to acquire the monitor. Seems very sub-optimal
    // 		ldr	r3, [JAZ_V1, #0]
    // 		sub	r1, Ristate, #8
    // 		orr	r3, r3, #1
    // 		str	r3, [r1, #0]
    // 	retry:
    // 		ldrex	r0, [JAZ_V1, #0]
    // 		cmp	r3, r0
    // 		bne	failed
    // 		strex	r0, r1, [JAZ_V1, #0]
    // 		cbz	r0, success
    // 		b	retry
    // 	failed:
    // 		<failed - someone else has the monitor - must yield>
    //  success:
    // 		<success - acquired the monitor>
    //
    ldr_imm(jinfo->codebuf, ARM_R3, JAZ_V1, 0, 1, 0);
    sub_imm(jinfo->codebuf, ARM_R1, Ristate, frame::interpreter_frame_monitor_size()*wordSize);
    orr_imm(jinfo->codebuf, ARM_R3, ARM_R3, 1);
    str_imm(jinfo->codebuf, ARM_R3, ARM_R1, 0, 1, 0);
    loc_retry = out_loc(jinfo->codebuf);
// retry:
    ldrex_imm(jinfo->codebuf, ARM_R0, JAZ_V1, 0);
    cmp_reg(jinfo->codebuf, ARM_R3, ARM_R0);
    loc_failed = forward_16(jinfo->codebuf);
    strex_imm(jinfo->codebuf, ARM_R0, ARM_R1, JAZ_V1, 0);
    loc_success = forward_16(jinfo->codebuf);
    branch_uncond(jinfo->codebuf, loc_retry);
    bcc_patch(jinfo->codebuf, COND_NE, loc_failed);
// failed:
    mov_imm(jinfo->codebuf, ARM_R0, 0+CONSTMETHOD_CODEOFFSET);
    bl(jinfo->codebuf, handlers[H_SYNCHRONIZED_ENTER]);
    loc_exception = forward_16(jinfo->codebuf);
    bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION_NO_REGS]);
    cbz_patch(jinfo->codebuf, ARM_R0, loc_exception);
    cbz_patch(jinfo->codebuf, ARM_R0, loc_success);
//    mov_imm(jinfo->codebuf, ARM_R0, 0+CONSTMETHOD_CODEOFFSET);
//    bl(jinfo->codebuf, handlers[H_MONITOR]);
// success:

  }

  {
    int nlocals = jinfo->method->max_locals();

    for (i = 0; i < nlocals; i++) {
      Reg r = jinfo->jregs->r_local[i];
      if (r) {
	unsigned stackdepth = 0;
	if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
	if (i < parms || (locals_info[i] & (1<<LOCAL_REF))) {
	  load_local(jinfo, r, i, stackdepth);
	}
      }
    }
  }
}

unsigned opcode2handler[] = {
  H_IDIV,
  H_LDIV,
  0, 0,			// fdiv, ddiv
  H_IREM,
  H_LREM,
  H_FREM,
  H_DREM,
  0, 0, 0, 0,		// ineg, lneg, fneg, dneg
  0, 0, 0, 0, 0, 0,	// shifts
  0, 0, 0, 0, 0, 0,	// and, or, xor
  0,			// iinc
  0,			// i2l
  H_I2F,
  H_I2D,
  0,			// l2i
  H_L2F,
  H_L2D,
  H_F2I,
  H_F2L,
  H_F2D,
  H_D2I,
  H_D2L,
  H_D2F,
};

#define OPCODE2HANDLER(opc) (handlers[opcode2handler[(opc)-opc_idiv]])

extern "C" void _ZN18InterpreterRuntime18register_finalizerEP10JavaThreadP7oopDesc(void);

void Thumb2_codegen(Thumb2_Info *jinfo, unsigned start)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;
  CodeBuf *codebuf = jinfo->codebuf;
  Thumb2_Stack *jstack = jinfo->jstack;
  unsigned bci;
  unsigned opcode;
  unsigned stackinfo;
  int len;
  unsigned stackdepth;

  for (bci = start; bci < code_size; ) {
#ifdef T2EE_PRINT_DISASS
    unsigned start_idx = jinfo->codebuf->idx;
    if (start_bci[start_idx] == -1) start_bci[start_idx] = bci;
#endif
    opcode = code_base[bci];
    stackinfo = bc_stackinfo[bci];

    if (stackinfo & BC_BRANCH_TARGET) Thumb2_Flush(jinfo);
    JASSERT(!(stackinfo & BC_COMPILED), "code already compiled for this bytecode?");
    stackdepth = stackinfo & ~BC_FLAGS_MASK;
    bc_stackinfo[bci] = (stackinfo & BC_FLAGS_MASK) | (codebuf->idx * 2) | BC_COMPILED;

    if (opcode > OPC_LAST_JAVA_OP && opcode != opc_return_register_finalizer) {
      if (Bytecodes::is_defined((Bytecodes::Code)opcode))
	opcode = (unsigned)Bytecodes::java_code((Bytecodes::Code)opcode);
    }

    len = Bytecodes::length_for((Bytecodes::Code)opcode);
    if (len <= 0) len = Bytecodes::special_length_at((address)(code_base+bci), (address)(code_base+code_size));

    if (IS_DEAD(stackinfo) || IS_ZOMBIE(stackinfo)) {
      unsigned zlen = 0;
#ifdef T2EE_PRINT_DISASS
      unsigned start_bci = bci;
#endif

      Thumb2_Exit(jinfo, H_ZOMBIE, bci, stackdepth);
      do {
	zlen += len;
	bci += len;
	if (bci >= code_size) break;
	opcode = code_base[bci];
	stackinfo = bc_stackinfo[bci];

	if (stackinfo & BC_BRANCH_TARGET) break;
	if (!(IS_DEAD(stackinfo) || IS_ZOMBIE(stackinfo))) break;

	bc_stackinfo[bci] = (stackinfo & BC_FLAGS_MASK) | (codebuf->idx * 2);

	if (opcode > OPC_LAST_JAVA_OP) {
	  if (Bytecodes::is_defined((Bytecodes::Code)opcode))
	    opcode = (unsigned)Bytecodes::java_code((Bytecodes::Code)opcode);
	}

	len = Bytecodes::length_for((Bytecodes::Code)opcode);
	if (len <= 0) len = Bytecodes::special_length_at((address)(code_base+bci), (address)(code_base+code_size));

      } while (1);
#ifdef T2EE_PRINT_DISASS
      end_bci[start_idx] = start_bci + zlen;
#endif
      jinfo->zombie_bytes += zlen;
      continue;
    }

#if 0
    if (bci >= 2620) {
      unsigned zlen = 0;
#ifdef T2EE_PRINT_DISASS
      unsigned start_bci = bci;
#endif

      Thumb2_Exit(jinfo, H_ZOMBIE, bci, stackdepth);
      do {
	zlen += len;
	bci += len;
	if (bci >= code_size) break;
	opcode = code_base[bci];
	stackinfo = bc_stackinfo[bci];

	if (stackinfo & BC_BRANCH_TARGET) break;

	if (opcode > OPC_LAST_JAVA_OP) {
	  if (Bytecodes::is_defined((Bytecodes::Code)opcode))
	    opcode = (unsigned)Bytecodes::java_code((Bytecodes::Code)opcode);
	}

	len = Bytecodes::length_for((Bytecodes::Code)opcode);
	if (len <= 0) len = Bytecodes::special_length_at((address)(code_base+bci), (address)(code_base+code_size));

      } while (1);
#ifdef T2EE_PRINT_DISASS
      end_bci[start_idx] = start_bci + zlen;
#endif
      jinfo->zombie_bytes += zlen;
      continue;
    }
#endif

#ifdef T2EE_PRINT_DISASS
    end_bci[start_idx] = bci + len;
#endif

    switch (opcode) {
      case opc_nop:
	break;
      case opc_aconst_null:
	len += Thumb2_Imm(jinfo, 0, bci+1);
	break;
      case opc_iconst_m1:
      case opc_iconst_0:
      case opc_iconst_1:
      case opc_iconst_2:
      case opc_iconst_3:
      case opc_iconst_4:
      case opc_iconst_5:
	len += Thumb2_Imm(jinfo, opcode - (unsigned)opc_iconst_0, bci+1);
	break;
      case opc_lconst_0:
      case opc_lconst_1:
	Thumb2_ImmX2(jinfo, opcode - (unsigned)opc_lconst_0, 0);
	break;
      case opc_fconst_0:
      case opc_fconst_1:
      case opc_fconst_2: {
	unsigned v = 0;
	if (opcode == (unsigned)opc_fconst_1) v = 0x3f800000;
	if (opcode == (unsigned)opc_fconst_2) v = 0x40000000;
	len += Thumb2_Imm(jinfo, v, bci+1);
	break;
      }
      case opc_dconst_0:
      case opc_dconst_1: {
	unsigned v_hi = 0;
	if (opcode == (unsigned)opc_dconst_1) v_hi = 0x3ff00000;
	Thumb2_ImmX2(jinfo, 0, v_hi);
	break;
      }
      case opc_bipush:
	len += Thumb2_Imm(jinfo, GET_JAVA_S1(code_base+bci+1), bci+2);
	break;
      case opc_sipush:
	len += Thumb2_Imm(jinfo, GET_JAVA_S2(code_base+bci+1), bci+3);
	break;
      case opc_ldc:
      case opc_ldc_w:
      case opc_ldc2_w: {
	unsigned index = (opcode == (unsigned)opc_ldc) ?
				code_base[bci+1] : GET_JAVA_U2(code_base+bci+1);
	constantPoolOop constants = jinfo->method->constants();
	unsigned v;

	switch (v = constants->tag_at(index).value()) {
	  case JVM_CONSTANT_Integer:
	  case JVM_CONSTANT_Float:
	    v = (unsigned)constants->int_at(index);
	    len += Thumb2_Imm(jinfo, v, bci+len);
	    break;
#if 0
	  case JVM_CONSTANT_String:
	    v = (unsigned)constants->resolved_string_at(index);
	    len += Thumb2_Imm(jinfo, v, bci+len);
	    break;
	  case JVM_CONSTANT_Class:
	    v = (unsigned)constants->resolved_klass_at(index)->klass_part()->java_mirror();
	    len += Thumb2_Imm(jinfo, v, bci+len);
	    break;
#endif
	  case JVM_CONSTANT_Long:
	  case JVM_CONSTANT_Double: {
	    unsigned long long v;
	    v = constants->long_at(index);
	    Thumb2_ImmX2(jinfo, v & 0xffffffff, v >> 32);
	    break;
	  }
	  case JVM_CONSTANT_Class:
	  case JVM_CONSTANT_String: {
	    Reg r;
	    Thumb2_Spill(jinfo, 1, 0);
	    r = JSTACK_REG(jstack);
	    PUSH(jstack, r);
	    ldr_imm(jinfo->codebuf, r, Ristate, ISTATE_METHOD, 1, 0);
	    ldr_imm(jinfo->codebuf, r, r, METHOD_CONSTANTS, 1, 0);
	    ldr_imm(jinfo->codebuf, r, r, CONSTANTPOOL_BASE + (index << 2), 1, 0);
	    if (v == JVM_CONSTANT_Class)
	      ldr_imm(jinfo->codebuf, r, r, KLASS_PART+KLASS_JAVA_MIRROR, 1, 0);
	    break;
	  }
	  default:
	    unsigned loc;

	    JASSERT(opcode != opc_ldc2_w, "ldc2_w unresolved?");
	    Thumb2_Flush(jinfo);
	    mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  Thumb2_save_locals(jinfo, stackdepth);
	    mov_imm(jinfo->codebuf, ARM_R1, opcode != opc_ldc);
	    bl(jinfo->codebuf, handlers[H_LDC]);
	  Thumb2_restore_locals(jinfo, stackdepth);
	    ldr_imm(jinfo->codebuf, ARM_R0, Rthread, THREAD_VM_RESULT, 1, 0);
	    mov_imm(jinfo->codebuf, ARM_R2, 0);
	    str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_VM_RESULT, 1, 0);
	    loc = forward_16(jinfo->codebuf);
	    bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	    cbnz_patch(jinfo->codebuf, ARM_R0, loc);
	    PUSH(jstack, ARM_R0);
	    break;
	}
	break;
      }

      case opc_iload:
      case opc_fload:
      case opc_aload:
	Thumb2_Load(jinfo, code_base[bci+1], stackdepth);
	break;
      case opc_lload:
      case opc_dload:
	Thumb2_LoadX2(jinfo, code_base[bci+1], stackdepth);
	break;
      case opc_iload_0:
      case opc_iload_1:
      case opc_iload_2:
      case opc_iload_3:
      case opc_fload_0:
      case opc_fload_1:
      case opc_fload_2:
      case opc_fload_3:
      case opc_aload_0:
      case opc_aload_1:
      case opc_aload_2:
      case opc_aload_3:
	Thumb2_Load(jinfo, (opcode - opc_iload_0) & 3, stackdepth);
	break;
      case opc_lload_0:
      case opc_lload_1:
      case opc_lload_2:
      case opc_lload_3:
      case opc_dload_0:
      case opc_dload_1:
      case opc_dload_2:
      case opc_dload_3:
	Thumb2_LoadX2(jinfo, (opcode - opc_iload_0) & 3, stackdepth);
	break;
      case opc_iaload:
      case opc_faload:
      case opc_aaload:
      case opc_baload:
      case opc_caload:
      case opc_saload:
	Thumb2_Xaload(jinfo, opcode);
	break;
      case opc_laload:
      case opc_daload:
	Thumb2_X2aload(jinfo);
	break;
      case opc_istore:
      case opc_fstore:
      case opc_astore:
	Thumb2_Store(jinfo, code_base[bci+1], stackdepth);
	break;
      case opc_lstore:
      case opc_dstore:
	Thumb2_StoreX2(jinfo, code_base[bci+1], stackdepth);
	break;
      case opc_istore_0:
      case opc_istore_1:
      case opc_istore_2:
      case opc_istore_3:
      case opc_fstore_0:
      case opc_fstore_1:
      case opc_fstore_2:
      case opc_fstore_3:
      case opc_astore_0:
      case opc_astore_1:
      case opc_astore_2:
      case opc_astore_3:
	Thumb2_Store(jinfo, (opcode - opc_istore_0) & 3, stackdepth);
	break;
      case opc_lstore_0:
      case opc_lstore_1:
      case opc_lstore_2:
      case opc_lstore_3:
      case opc_dstore_0:
      case opc_dstore_1:
      case opc_dstore_2:
      case opc_dstore_3:
	Thumb2_StoreX2(jinfo, (opcode - opc_istore_0) & 3, stackdepth);
	break;
      case opc_iastore:
      case opc_fastore:
      case opc_bastore:
      case opc_castore:
      case opc_sastore:
	Thumb2_Xastore(jinfo, opcode);
	break;
      case opc_lastore:
      case opc_dastore:
	Thumb2_X2astore(jinfo);
	break;

      case opc_pop:
      case opc_pop2:
	Thumb2_Pop(jinfo, opcode - opc_pop + 1);
	break;

      case opc_dup:
      case opc_dup_x1:
      case opc_dup_x2:
	Thumb2_Dup(jinfo, opcode - opc_dup);
	break;

      case opc_dup2:
      case opc_dup2_x1:
      case opc_dup2_x2:
	Thumb2_Dup2(jinfo, opcode - opc_dup2);
	break;

      case opc_swap:
	Thumb2_Swap(jinfo);
	break;

      case opc_iadd:
      case opc_isub:
      case opc_imul:
      case opc_ishl:
      case opc_ishr:
      case opc_iushr:
      case opc_iand:
      case opc_ior:
      case opc_ixor:
	Thumb2_iOp(jinfo, opcode);
	break;

      case opc_ladd:
      case opc_lsub:
      case opc_land:
      case opc_lor:
      case opc_lxor:
	Thumb2_lOp(jinfo, opcode);
	break;

      case opc_lshl: {
	Reg lho_lo, lho_hi, res_lo, res_hi, shift;
	unsigned loc1, loc2;

	Thumb2_Fill(jinfo, 3);
	shift = POP(jstack);
	lho_lo = POP(jstack);
	lho_hi = POP(jstack);
	Thumb2_Spill(jinfo, 2, (1<<lho_lo)|(1<<lho_hi));
	res_hi = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	JASSERT(res_lo != lho_lo && res_lo != lho_hi, "Spill failed");
	JASSERT(res_hi != lho_lo && res_hi != lho_hi, "Spill failed");
	and_imm(jinfo->codebuf, ARM_IP, shift, 31);
	tst_imm(jinfo->codebuf, shift, 32);
	loc1 = forward_16(jinfo->codebuf);
	mov_imm(jinfo->codebuf, res_lo, 0);
	dop_reg(jinfo->codebuf, DP_LSL, res_hi, lho_lo, ARM_IP, SHIFT_LSL, 0);
	loc2 = forward_16(jinfo->codebuf);
	bcc_patch(jinfo->codebuf, COND_EQ, loc1);
	dop_reg(jinfo->codebuf, DP_LSL, res_lo, lho_lo, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_LSL, res_hi, lho_hi, ARM_IP, SHIFT_LSL, 0);
	rsb_imm(jinfo->codebuf, ARM_IP, ARM_IP, 32);
	dop_reg(jinfo->codebuf, DP_LSR, ARM_IP, lho_lo, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_ORR, res_hi, res_hi, ARM_IP, SHIFT_LSL, 0);
	branch_narrow_patch(jinfo->codebuf, loc2);
	break;
      }

      case opc_lushr: {
	Reg lho_lo, lho_hi, res_lo, res_hi, shift;
	unsigned loc1, loc2;

	Thumb2_Fill(jinfo, 3);
	shift = POP(jstack);
	lho_lo = POP(jstack);
	lho_hi = POP(jstack);
	Thumb2_Spill(jinfo, 2, (1<<lho_lo)|(1<<lho_hi));
	res_hi = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	JASSERT(res_lo != lho_lo && res_lo != lho_hi, "Spill failed");
	JASSERT(res_hi != lho_lo && res_hi != lho_hi, "Spill failed");
	and_imm(jinfo->codebuf, ARM_IP, shift, 31);
	tst_imm(jinfo->codebuf, shift, 32);
	loc1 = forward_16(jinfo->codebuf);
	mov_imm(jinfo->codebuf, res_hi, 0);
	dop_reg(jinfo->codebuf, DP_LSR, res_lo, lho_hi, ARM_IP, SHIFT_LSL, 0);
	loc2 = forward_16(jinfo->codebuf);
	bcc_patch(jinfo->codebuf, COND_EQ, loc1);
	dop_reg(jinfo->codebuf, DP_LSR, res_hi, lho_hi, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_LSR, res_lo, lho_lo, ARM_IP, SHIFT_LSL, 0);
	rsb_imm(jinfo->codebuf, ARM_IP, ARM_IP, 32);
	dop_reg(jinfo->codebuf, DP_LSL, ARM_IP, lho_hi, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_ORR, res_lo, res_lo, ARM_IP, SHIFT_LSL, 0);
	branch_narrow_patch(jinfo->codebuf, loc2);
	break;
      }

      case opc_lshr: {
	Reg lho_lo, lho_hi, res_lo, res_hi, shift;
	unsigned loc1, loc2;

	Thumb2_Fill(jinfo, 3);
	shift = POP(jstack);
	lho_lo = POP(jstack);
	lho_hi = POP(jstack);
	Thumb2_Spill(jinfo, 2, (1<<lho_lo)|(1<<lho_hi));
	res_hi = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	res_lo = PUSH(jstack, JSTACK_PREFER(jstack, ~((1<<lho_lo)|(1<<lho_hi))));
	JASSERT(res_lo != lho_lo && res_lo != lho_hi, "Spill failed");
	JASSERT(res_hi != lho_lo && res_hi != lho_hi, "Spill failed");
	and_imm(jinfo->codebuf, ARM_IP, shift, 31);
	tst_imm(jinfo->codebuf, shift, 32);
	loc1 = forward_16(jinfo->codebuf);
	asr_imm(jinfo->codebuf, res_hi, lho_hi, 31);
	dop_reg(jinfo->codebuf, DP_ASR, res_lo, lho_hi, ARM_IP, SHIFT_LSL, 0);
	loc2 = forward_16(jinfo->codebuf);
	bcc_patch(jinfo->codebuf, COND_EQ, loc1);
	dop_reg(jinfo->codebuf, DP_ASR, res_hi, lho_hi, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_LSR, res_lo, lho_lo, ARM_IP, SHIFT_LSL, 0);
	rsb_imm(jinfo->codebuf, ARM_IP, ARM_IP, 32);
	dop_reg(jinfo->codebuf, DP_LSL, ARM_IP, lho_hi, ARM_IP, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_ORR, res_lo, res_lo, ARM_IP, SHIFT_LSL, 0);
	branch_narrow_patch(jinfo->codebuf, loc2);
	break;
      }

      case opc_lmul:
	Thumb2_lmul(jinfo);
	break;

      case opc_fadd:
      case opc_fsub:
      case opc_fmul:
      case opc_fdiv:
	Thumb2_fOp(jinfo, opcode);
	break;

      case opc_dadd:
      case opc_dsub:
      case opc_dmul:
      case opc_ddiv:
	Thumb2_dOp(jinfo, opcode);
	break;

      case opc_fcmpl:
      case opc_fcmpg: {
	Thumb2_Stack *jstack = jinfo->jstack;
	unsigned rho, lho, res;
	unsigned loc1, loc2, loc_ne;

	Thumb2_Fill(jinfo, 2);
	rho = POP(jstack);
	lho = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	res = PUSH(jstack, JSTACK_REG(jstack));
	vmov_reg_s_toVFP(jinfo->codebuf, VFP_S0, lho);
	vmov_reg_s_toVFP(jinfo->codebuf, VFP_S1, rho);
	vcmp_reg_s(jinfo->codebuf, VFP_S0, VFP_S1, 1);
	mov_imm(jinfo->codebuf, res, opcode == opc_fcmpl ? 1 : -1);
	vmrs(jinfo->codebuf, ARM_PC);
	loc1 = forward_16(jinfo->codebuf);
	dop_imm_preserve(jinfo->codebuf, DP_RSB, res, res, 0);
	loc2 = forward_16(jinfo->codebuf);
	vcmp_reg_s(jinfo->codebuf, VFP_S0, VFP_S1, 0);
	loc_ne = forward_16(jinfo->codebuf);
	mov_imm(jinfo->codebuf, res, 0);
	bcc_patch(jinfo->codebuf, opcode == opc_fcmpl ? COND_GT : COND_MI, loc1);
	bcc_patch(jinfo->codebuf, opcode == opc_fcmpl ? COND_MI : COND_GT, loc2);
	bcc_patch(jinfo->codebuf, COND_NE, loc_ne);
	break;
      }

      case opc_dcmpl:
      case opc_dcmpg: {
	Thumb2_Stack *jstack = jinfo->jstack;
	unsigned rho_lo, rho_hi, lho_lo, lho_hi, res;
	unsigned loc1, loc2, loc_ne;

	Thumb2_Fill(jinfo, 4);
	rho_lo = POP(jstack);
	rho_hi = POP(jstack);
	lho_lo = POP(jstack);
	lho_hi = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	res = PUSH(jstack, JSTACK_REG(jstack));
	vmov_reg_d_toVFP(jinfo->codebuf, VFP_S0, lho_lo, lho_hi);
	vmov_reg_d_toVFP(jinfo->codebuf, VFP_S1, rho_lo, rho_hi);
	vcmp_reg_d(jinfo->codebuf, VFP_S0, VFP_S1, 1);
	mov_imm(jinfo->codebuf, res, opcode == opc_dcmpl ? 1 : -1);
	vmrs(jinfo->codebuf, ARM_PC);
	loc1 = forward_16(jinfo->codebuf);
	dop_imm_preserve(jinfo->codebuf, DP_RSB, res, res, 0);
	loc2 = forward_16(jinfo->codebuf);
	vcmp_reg_d(jinfo->codebuf, VFP_S0, VFP_S1, 0);
	loc_ne = forward_16(jinfo->codebuf);
	mov_imm(jinfo->codebuf, res, 0);
	bcc_patch(jinfo->codebuf, opcode == opc_dcmpl ? COND_GT : COND_MI, loc1);
	bcc_patch(jinfo->codebuf, opcode == opc_dcmpl ? COND_MI : COND_GT, loc2);
	bcc_patch(jinfo->codebuf, COND_NE, loc_ne);
	break;
      }

      case opc_drem:
      case opc_lrem:
      case opc_ldiv: {
	Reg src[4], dst[4];

	Thumb2_Fill(jinfo, 4);
	src[2] = POP(jstack);
	src[3] = POP(jstack);
	src[0] = POP(jstack);
	src[1] = POP(jstack);
	Thumb2_Flush(jinfo);
	dst[0] = ARM_R0;
	dst[1] = ARM_R1;
	dst[2] = ARM_R2;
	dst[3] = ARM_R3;
	mov_multiple(jinfo->codebuf, dst, src, 4);
	bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
	if (opcode != opc_lrem) {
	  PUSH(jstack, ARM_R1);
	  PUSH(jstack, ARM_R0);
	} else {
	  PUSH(jstack, ARM_R3);
	  PUSH(jstack, ARM_R2);
	}
	break;
      }

      case opc_frem:
      case opc_idiv:
      case opc_irem: {
	Reg r_rho, r_lho;

	Thumb2_Fill(jinfo, 2);
	r_rho = POP(jstack);
	r_lho = POP(jstack);
	Thumb2_Flush(jinfo);
	if (r_rho == ARM_R0) {
	  if (r_lho == ARM_R1) {
	    mov_reg(jinfo->codebuf, ARM_IP, r_rho);
	    mov_reg(jinfo->codebuf, ARM_R0, r_lho);
	    mov_reg(jinfo->codebuf, ARM_R1, ARM_IP);
	  } else {
	    mov_reg(jinfo->codebuf, ARM_R1, r_rho);
	    mov_reg(jinfo->codebuf, ARM_R0, r_lho);
	  }
	} else {
	  mov_reg(jinfo->codebuf, ARM_R0, r_lho);
	  mov_reg(jinfo->codebuf, ARM_R1, r_rho);
	}
#if 1
	if (opcode == opc_frem)
	  bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
	else
	  blx(jinfo->codebuf, OPCODE2HANDLER(opcode));
#else
	bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
#endif
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_f2i:
      case opc_i2f: {
	Reg r;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R0, r);
	bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_f2d:
      case opc_f2l:
      case opc_i2d: {
	Reg r;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R0, r);
	bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
	PUSH(jstack, ARM_R1);
	PUSH(jstack, ARM_R0);
	break;
    }

      case opc_d2f:
      case opc_d2i:
      case opc_l2d:
      case opc_d2l:
      case opc_l2f: {
	Reg lo, hi;

	Thumb2_Fill(jinfo, 2);
	lo = POP(jstack);
	hi = POP(jstack);
	Thumb2_Flush(jinfo);
	if (hi == ARM_R0) {
	  if (lo == ARM_R1) {
	    mov_reg(jinfo->codebuf, ARM_IP, hi);
	    mov_reg(jinfo->codebuf, ARM_R0, lo);
	    mov_reg(jinfo->codebuf, ARM_R1, ARM_IP);
	  } else {
	    mov_reg(jinfo->codebuf, ARM_R1, hi);
	    mov_reg(jinfo->codebuf, ARM_R0, lo);
	  }
	} else {
	  mov_reg(jinfo->codebuf, ARM_R0, lo);
	  mov_reg(jinfo->codebuf, ARM_R1, hi);
	}
	bl(jinfo->codebuf, OPCODE2HANDLER(opcode));
	if (opcode == opc_l2d || opcode == opc_d2l) PUSH(jstack, ARM_R1);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_ineg:
	Thumb2_iNeg(jinfo, opcode);
	break;

      case opc_lneg:
	Thumb2_lNeg(jinfo, opcode);
	break;

      case opc_fneg:
	Thumb2_fNeg(jinfo, opcode);
	break;

      case opc_dneg:
	Thumb2_dNeg(jinfo, opcode);
	break;

      case opc_i2l: {
	unsigned r, r_res_lo, r_res_hi;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Spill(jinfo, 2, 0);
	r_res_hi = PUSH(jstack, JSTACK_REG(jstack));
	r_res_lo = PUSH(jstack, JSTACK_REG(jstack));
	if (r == r_res_hi) {
	  SWAP(jstack);
	  r_res_hi = r_res_lo;
	  r_res_lo = r;
	}
	mov_reg(jinfo->codebuf, r_res_lo, r);
	asr_imm(jinfo->codebuf, r_res_hi, r, 31);
	break;
      }

      case opc_l2i: {
	unsigned r_lo, r_hi;
	unsigned r;

	Thumb2_Fill(jinfo, 2);
	r_lo = POP(jstack);
	r_hi = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	r = PUSH(jstack, r_lo);
	break;
      }

      case opc_i2b: {
	unsigned r_src, r_dst;

	Thumb2_Fill(jinfo, 1);
	r_src = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	r_dst = PUSH(jstack, JSTACK_REG(jstack));
	sxtb(jinfo->codebuf, r_dst, r_src);
	break;
      }

      case opc_i2s: {
	unsigned r_src, r_dst;

	Thumb2_Fill(jinfo, 1);
	r_src = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	r_dst = PUSH(jstack, JSTACK_REG(jstack));
	sxth(jinfo->codebuf, r_dst, r_src);
	break;
      }

      case opc_i2c: {
	unsigned r_src, r_dst;

	Thumb2_Fill(jinfo, 1);
	r_src = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	r_dst = PUSH(jstack, JSTACK_REG(jstack));
	uxth(jinfo->codebuf, r_dst, r_src);
	break;
      }

      case opc_lcmp: {
	unsigned lho_lo, lho_hi;
	unsigned rho_lo, rho_hi;
	unsigned r_tmp_lo, r_tmp_hi;
	unsigned res;
	unsigned loc_lt, loc_eq;

	Thumb2_Fill(jinfo, 4);
	rho_lo = POP(jstack);
	rho_hi = POP(jstack);
	lho_lo = POP(jstack);
	lho_hi = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	res = JSTACK_REG(jstack);
	PUSH(jstack, res);
	r_tmp_lo = Thumb2_Tmp(jinfo, (1<<rho_lo)|(1<<rho_hi)|(1<<lho_lo)|(1<<lho_hi));
	r_tmp_hi = Thumb2_Tmp(jinfo, (1<<rho_lo)|(1<<rho_hi)|(1<<lho_lo)|(1<<lho_hi)|(1<<r_tmp_lo));
	dop_reg(jinfo->codebuf, DP_SUB, r_tmp_lo, lho_lo, rho_lo, SHIFT_LSL, 0);
	dop_reg(jinfo->codebuf, DP_SBC, r_tmp_hi, lho_hi, rho_hi, SHIFT_LSL, 0);
	mov_imm(jinfo->codebuf, res, (unsigned)-1);
	loc_lt = forward_16(jinfo->codebuf);
	dop_reg(jinfo->codebuf, DP_ORR, res, r_tmp_lo, r_tmp_hi, SHIFT_LSL, 0);
	loc_eq = forward_16(jinfo->codebuf);
	mov_imm(jinfo->codebuf, res, 1);
	bcc_patch(jinfo->codebuf, COND_LT, loc_lt);
	bcc_patch(jinfo->codebuf, COND_EQ, loc_eq);
	break;
      }

      case opc_iinc: {
	unsigned local = code_base[bci+1];
	int constant = GET_JAVA_S1(code_base+bci+2);
	unsigned r = jinfo->jregs->r_local[local];

	if (!r) {
	  int nlocals = jinfo->method->max_locals();
	  r = Thumb2_Tmp(jinfo, 0);
	  stackdepth -= jstack->depth;
	  if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
	  load_local(jinfo, r, local, stackdepth);
	  add_imm(jinfo->codebuf, r, r, constant);
	  store_local(jinfo, r, local, stackdepth);
	} else {
	  Thumb2_Corrupt(jinfo, r, 0);
	  add_imm(jinfo->codebuf, r, r, constant);
	}
	break;
      }

      case opc_getfield: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);
	Reg r_obj;

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  int java_index = GET_JAVA_U2(code_base+bci+1);
	  constantPoolOop pool = jinfo->method->constants();
	  symbolOop sig = pool->signature_ref_at(java_index);
	  jbyte *base = sig->base();
	  jbyte c = *base;
	  int handler = H_GETFIELD_WORD;

	  if (c == 'J' || c == 'D') handler = H_GETFIELD_DW;
	  if (c == 'B' || c == 'Z') handler = H_GETFIELD_SB;
	  if (c == 'C') handler = H_GETFIELD_H;
	  if (c == 'S') handler = H_GETFIELD_SH;
	  Thumb2_Flush(jinfo);
	  Thumb2_save_locals(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf, handlers[handler]);
	  Thumb2_restore_locals(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	TosState tos_type = cache->flag_state();
	int field_offset = cache->f2();

	if (tos_type == ltos || tos_type == dtos) {
	  Reg r_lo, r_hi;
	  Thumb2_Fill(jinfo, 1);
	  r_obj = POP(jstack);
	  Thumb2_Spill(jinfo, 2, 0);
	  r_hi = PUSH(jstack, JSTACK_REG(jstack));
	  r_lo = PUSH(jstack, JSTACK_REG(jstack));
	  ldrd_imm(jinfo->codebuf, r_lo, r_hi, r_obj, field_offset, 1, 0);
	} else {
	  Reg r;

	  Thumb2_Fill(jinfo, 1);
	  r_obj = POP(jstack);
	  Thumb2_Spill(jinfo, 1, 0);
	  r = JSTACK_REG(jstack);
	  PUSH(jstack, r);
	  if (tos_type == btos)
	    ldrsb_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else if (tos_type == ctos)
	    ldrh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else if (tos_type == stos)
	    ldrsh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else
	    ldr_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	}
	break;
      }

      case opc_monitorexit:
      case opc_monitorenter:
	  Thumb2_Exit(jinfo, H_MONITOR, bci, stackdepth);
	  break;

      case opc_getstatic: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  int java_index = GET_JAVA_U2(code_base+bci+1);
	  constantPoolOop pool = jinfo->method->constants();
	  symbolOop sig = pool->signature_ref_at(java_index);
	  jbyte *base = sig->base();
	  jbyte c = *base;
	  int handler = H_GETSTATIC_WORD;

	  if (c == 'J' || c == 'D') handler = H_GETSTATIC_DW;
	  if (c == 'B' || c == 'Z') handler = H_GETSTATIC_SB;
	  if (c == 'C') handler = H_GETSTATIC_H;
	  if (c == 'S') handler = H_GETSTATIC_SH;
	  Thumb2_Flush(jinfo);
	  Thumb2_save_locals(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf, handlers[handler]);
	  Thumb2_restore_locals(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	TosState tos_type = cache->flag_state();
	int field_offset = cache->f2();

	if (tos_type == ltos || tos_type == dtos) {
	  Reg r_lo, r_hi;
	  Thumb2_Spill(jinfo, 2, 0);
	  r_hi = PUSH(jstack, JSTACK_REG(jstack));
	  r_lo = PUSH(jstack, JSTACK_REG(jstack));
	  ldr_imm(jinfo->codebuf, r_lo, Ristate, ISTATE_CONSTANTS, 1, 0);
	  ldr_imm(jinfo->codebuf, r_lo, r_lo, CP_OFFSET + (index << 4) + 4, 1, 0);
	  ldrd_imm(jinfo->codebuf, r_lo, r_hi, r_lo, field_offset, 1, 0);
	} else {
	  Reg r;
	  Thumb2_Spill(jinfo, 1, 0);
	  r = JSTACK_REG(jstack);
	  PUSH(jstack, r);
	  ldr_imm(jinfo->codebuf, r, Ristate, ISTATE_CONSTANTS, 1, 0);
	  ldr_imm(jinfo->codebuf, r, r, CP_OFFSET + (index << 4) + 4, 1, 0);
	  if (tos_type == btos)
	    ldrsb_imm(jinfo->codebuf, r, r, field_offset, 1, 0);
	  else if (tos_type == ctos)
	    ldrh_imm(jinfo->codebuf, r, r, field_offset, 1, 0);
	  else if (tos_type == stos)
	    ldrsh_imm(jinfo->codebuf, r, r, field_offset, 1, 0);
	  else
	    ldr_imm(jinfo->codebuf, r, r, field_offset, 1, 0);
	}
	break;
      }

      case opc_putfield: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);
	Reg r_obj;

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  int java_index = GET_JAVA_U2(code_base+bci+1);
	  constantPoolOop pool = jinfo->method->constants();
	  symbolOop sig = pool->signature_ref_at(java_index);
	  jbyte *base = sig->base();
	  jbyte c = *base;
	  int handler = H_PUTFIELD_WORD;

	  if (c == 'J' || c == 'D') handler = H_PUTFIELD_DW;
	  if (c == 'B' || c == 'Z') handler = H_PUTFIELD_B;
	  if (c == 'C' || c == 'S') handler = H_PUTFIELD_H;
	  if (c == '[' || c == 'L') handler = H_PUTFIELD_A;
	  Thumb2_Flush(jinfo);
	  Thumb2_save_locals(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf, handlers[handler]);
	  Thumb2_restore_locals(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	TosState tos_type = cache->flag_state();
	int field_offset = cache->f2();

	if (tos_type == ltos || tos_type == dtos) {
	  Reg r_lo, r_hi;
	  Thumb2_Fill(jinfo, 3);
	  r_lo = POP(jstack);
	  r_hi = POP(jstack);
	  r_obj = POP(jstack);
	  strd_imm(jinfo->codebuf, r_lo, r_hi, r_obj, field_offset, 1, 0);
	} else {
	  Reg r;
	  Thumb2_Fill(jinfo, 2);
	  r = POP(jstack);
	  r_obj = POP(jstack);
	  if (tos_type == btos)
	    strb_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else if (tos_type == ctos | tos_type == stos)
	    strh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else {
	    str_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    if (tos_type == atos) {
	      Thumb2_Flush(jinfo);
	      mov_reg(jinfo->codebuf, ARM_R0, r_obj);
	      bl(jinfo->codebuf, handlers[H_APUTFIELD]);
	    }
	  }
	}
	break;
      }

      case opc_putstatic: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  int java_index = GET_JAVA_U2(code_base+bci+1);
	  constantPoolOop pool = jinfo->method->constants();
	  symbolOop sig = pool->signature_ref_at(java_index);
	  jbyte *base = sig->base();
	  jbyte c = *base;
	  int handler = H_PUTSTATIC_WORD;

	  if (c == 'J' || c == 'D') handler = H_PUTSTATIC_DW;
	  if (c == 'B' || c == 'Z') handler = H_PUTSTATIC_B;
	  if (c == 'C' || c == 'S') handler = H_PUTSTATIC_H;
	  if (c == '[' || c == 'L') handler = H_PUTSTATIC_A;
	  Thumb2_Flush(jinfo);
	  Thumb2_save_locals(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf, handlers[handler]);
	  Thumb2_restore_locals(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	TosState tos_type = cache->flag_state();
	int field_offset = cache->f2();
	Reg r_obj;

	if (tos_type == ltos || tos_type == dtos) {
	  Reg r_lo, r_hi;
	  Thumb2_Fill(jinfo, 2);
	  r_lo = POP(jstack);
	  r_hi = POP(jstack);
	  Thumb2_Spill(jinfo, 1, (1<<r_lo)|(1<<r_hi));
	  r_obj = JSTACK_PREFER(jstack, ~((1<<r_lo)|(1<<r_hi)));
	  JASSERT(r_obj != r_lo && r_obj != r_hi, "corruption in putstatic");
	  ldr_imm(jinfo->codebuf, r_obj, Ristate, ISTATE_CONSTANTS, 1, 0);
	  ldr_imm(jinfo->codebuf, r_obj, r_obj, CP_OFFSET + (index << 4) + 4, 1, 0);
	  strd_imm(jinfo->codebuf, r_lo, r_hi, r_obj, field_offset, 1, 0);
	} else {
	  Reg r;
	  Thumb2_Fill(jinfo, 1);
	  r = POP(jstack);
	  Thumb2_Spill(jinfo, 1, (1<<r));
	  r_obj = JSTACK_PREFER(jstack, ~(1<<r));
	  JASSERT(r_obj != r, "corruption in putstatic");
	  ldr_imm(jinfo->codebuf, r_obj, Ristate, ISTATE_CONSTANTS, 1, 0);
	  ldr_imm(jinfo->codebuf, r_obj, r_obj, CP_OFFSET + (index << 4) + 4, 1, 0);
	  if (tos_type == btos)
	    strb_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else if (tos_type == ctos | tos_type == stos)
	    strh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	  else {
	    str_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    if (tos_type == atos) {
	      Thumb2_Flush(jinfo);
	      mov_reg(jinfo->codebuf, ARM_R0, r_obj);
	      bl(jinfo->codebuf, handlers[H_APUTFIELD]);
	    }
	  }
	}
	break;
      }

      case opc_invokestatic:
      case opc_invokespecial: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);
	unsigned loc;
	methodOop callee;

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  Thumb2_Flush(jinfo);
	  Thumb2_invoke_save(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf,
	    handlers[opcode == opc_invokestatic ? H_INVOKESTATIC : H_INVOKESPECIAL]);
	  Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	callee = (methodOop)cache->f1();
	if (callee->is_accessor()) {
	  u1 *code = callee->code_base();
	  int index = GET_NATIVE_U2(&code[2]);
	  constantPoolCacheOop callee_cache = callee->constants()->cache();
	  ConstantPoolCacheEntry *entry = callee_cache->entry_at(index);
	  Reg r_obj, r;

	  if (entry->is_resolved(Bytecodes::_getfield)) {
#if 0
	    tty->print("Inlining accessor (opcode = %s) ", opcode == opc_invokestatic ? "invokestatic" : "invokespecial");
	    callee->print_short_name(tty);
	    tty->print("\n");
#endif
	    JASSERT(cache->parameter_size() == 1, "not 1 parameter to accessor");

	    TosState tos_type = entry->flag_state();
	    int field_offset = entry->f2();

	    JASSERT(tos_type == btos || tos_type == ctos || tos_type == stos || tos_type == atos || tos_type == itos, "not itos or atos");

	    Thumb2_Fill(jinfo, 1);
	    r_obj = POP(jstack);
	    Thumb2_Spill(jinfo, 1, 0);
	    r = JSTACK_REG(jstack);
	    PUSH(jstack, r);
	    if (tos_type == btos)
	      ldrb_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    else if (tos_type == ctos)
	      ldrh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    else if (tos_type == stos)
	      ldrsh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    else
	      ldr_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	    break;
	  }
	}

	Thumb2_Flush(jinfo);
  ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_METHOD, 1, 0);
	ldr_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_CONSTANTS, 1, 0);
	mov_imm(jinfo->codebuf, ARM_R1, 0);
  ldr_imm(jinfo->codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
	if (opcode == opc_invokespecial)
	  ldr_imm(jinfo->codebuf, ARM_R3, Rstack, (cache->parameter_size()-1) * sizeof(int), 1, 0);
	ldr_imm(jinfo->codebuf, ARM_R0, ARM_R0, CP_OFFSET + (index << 4) + 4, 1, 0);
  add_imm(jinfo->codebuf, ARM_R2, ARM_R2, bci+CONSTMETHOD_CODEOFFSET);
	if (opcode == opc_invokespecial)
	  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R3, 0, 1, 0); // Null pointer check - cbz better?
	str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	ldr_imm(jinfo->codebuf, ARM_R1, ARM_R0, METHOD_FROM_INTERPRETED, 1, 0);
  str_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_BCP, 1, 0);
	str_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	  Thumb2_Debug(jinfo, H_DEBUG_METHODCALL);
	Thumb2_invoke_save(jinfo, stackdepth);
  sub_imm(jinfo->codebuf, Rstack, Rstack, 4);
	ldr_imm(jinfo->codebuf, ARM_R3, ARM_R1, 0, 1, 0);
	mov_reg(jinfo->codebuf, ARM_R2, Rthread);
  str_imm(jinfo->codebuf, Rstack, Ristate, ISTATE_STACK, 1, 0);
add_imm(jinfo->codebuf, ARM_R3, ARM_R3, CODE_ALIGN_SIZE);
//	enter_leave(jinfo->codebuf, 0);
	blx_reg(jinfo->codebuf, ARM_R3);
//	enter_leave(jinfo->codebuf, 1);
  ldr_imm(jinfo->codebuf, Rthread, Ristate, ISTATE_THREAD, 1, 0);
#ifdef USE_RLOCAL
  ldr_imm(jinfo->codebuf, Rlocals, Ristate, ISTATE_LOCALS, 1, 0);
#endif
	ldr_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_STACK_LIMIT, 1, 0);
	JASSERT(!(bc_stackinfo[bci+len] & BC_COMPILED), "code already compiled for this bytecode?");
	Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	ldr_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_TOP_ZERO_FRAME, 1, 0);
	add_imm(jinfo->codebuf, ARM_R2, ARM_R2, 4);
	ldr_imm(jinfo->codebuf, ARM_R3, Rthread, THREAD_PENDING_EXC, 1, 0);
	str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_JAVA_SP, 1, 0);
	str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R3, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION_NO_REGS]);
	break;
      }

      case opc_invokeinterface: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);
	unsigned loc, loc_inc_ex;

// Currently we just call the unresolved invokeinterface entry for resolved /
// unresolved alike!
    Thumb2_Flush(jinfo);
    Thumb2_invoke_save(jinfo, stackdepth);
    mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
    mov_imm(jinfo->codebuf, ARM_R1, index);
    blx(jinfo->codebuf, handlers[H_INVOKEINTERFACE]);
    Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	break;
      }

      case opc_invokevirtual: {
	constantPoolCacheOop  cp = jinfo->method->constants()->cache();
        ConstantPoolCacheEntry* cache;
	int index = GET_NATIVE_U2(code_base+bci+1);
	unsigned loc;

        cache = cp->entry_at(index);
        if (!cache->is_resolved((Bytecodes::Code)opcode)) {
	  Thumb2_Flush(jinfo);
	  Thumb2_invoke_save(jinfo, stackdepth);
	  mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	  mov_imm(jinfo->codebuf, ARM_R1, index);
	  blx(jinfo->codebuf, handlers[H_INVOKEVIRTUAL]);
	  Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  break;
	}

	if (cache->is_vfinal()) {
	  methodOop callee = (methodOop)cache->f2();
	  if (callee->is_accessor()) {
	    u1 *code = callee->code_base();
	    int index = GET_NATIVE_U2(&code[2]);
	    constantPoolCacheOop callee_cache = callee->constants()->cache();
	    ConstantPoolCacheEntry *entry = callee_cache->entry_at(index);
	    Reg r_obj, r;

	    if (entry->is_resolved(Bytecodes::_getfield)) {
#if 0
	      tty->print("Inlining accessor (opcode = invokevfinal) ");
	      callee->print_short_name(tty);
	      tty->print("\n");
#endif
	      JASSERT(cache->parameter_size() == 1, "not 1 parameter to accessor");

	      TosState tos_type = entry->flag_state();
	      int field_offset = entry->f2();

	      JASSERT(tos_type == btos || tos_type == ctos || tos_type == stos || tos_type == atos || tos_type == itos, "not itos or atos");

	      Thumb2_Fill(jinfo, 1);
	      r_obj = POP(jstack);
	      Thumb2_Spill(jinfo, 1, 0);
	      r = JSTACK_REG(jstack);
	      PUSH(jstack, r);
	      if (tos_type == btos)
		ldrb_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	      else if (tos_type == ctos)
		ldrh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	      else if (tos_type == stos)
		ldrsh_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	      else
		ldr_imm(jinfo->codebuf, r, r_obj, field_offset, 1, 0);
	      break;
	    }
	  }
	}

	Thumb2_Flush(jinfo);
	if (cache->is_vfinal()) {
  ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_METHOD, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_CONSTANTS, 1, 0);
	  mov_imm(jinfo->codebuf, ARM_R1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R3, Rstack, (cache->parameter_size()-1) * sizeof(int), 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R0, ARM_R0, CP_OFFSET + (index << 4) + 8, 1, 0);
  ldr_imm(jinfo->codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R3, 0, 1, 0); // Null pointer check - cbz better?
	  str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R1, ARM_R0, METHOD_FROM_INTERPRETED, 1, 0);
  add_imm(jinfo->codebuf, ARM_R2, ARM_R2, bci+CONSTMETHOD_CODEOFFSET);
	  str_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	  Thumb2_Debug(jinfo, H_DEBUG_METHODCALL);
	Thumb2_invoke_save(jinfo, stackdepth);
  sub_imm(jinfo->codebuf, Rstack, Rstack, 4);
	  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R1, 0, 1, 0);
  str_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_BCP, 1, 0);
	  mov_reg(jinfo->codebuf, ARM_R2, Rthread);
  str_imm(jinfo->codebuf, Rstack, Ristate, ISTATE_STACK, 1, 0);
add_imm(jinfo->codebuf, ARM_R3, ARM_R3, CODE_ALIGN_SIZE);
//	  enter_leave(jinfo->codebuf, 0);
	  blx_reg(jinfo->codebuf, ARM_R3);
//	  enter_leave(jinfo->codebuf, 1);
  ldr_imm(jinfo->codebuf, Rthread, Ristate, ISTATE_THREAD, 1, 0);
#ifdef USE_RLOCAL
  ldr_imm(jinfo->codebuf, Rlocals, Ristate, ISTATE_LOCALS, 1, 0);
#endif
	  ldr_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_STACK_LIMIT, 1, 0);
	JASSERT(!(bc_stackinfo[bci+len] & BC_COMPILED), "code already compiled for this bytecode?");
	Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  ldr_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_TOP_ZERO_FRAME, 1, 0);
	  add_imm(jinfo->codebuf, ARM_R2, ARM_R2, 4);
	  ldr_imm(jinfo->codebuf, ARM_R3, Rthread, THREAD_PENDING_EXC, 1, 0);
	  str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_JAVA_SP, 1, 0);
	  str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R3, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION_NO_REGS]);
	  break;
	} else {
  ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_METHOD, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R3, Rstack, (cache->parameter_size()-1) * sizeof(int), 1, 0);
  ldr_imm(jinfo->codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R3, 4, 1, 0);
	  mov_imm(jinfo->codebuf, ARM_R1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R0, ARM_R3, INSTANCEKLASS_VTABLE_OFFSET + cache->f2() * 4, 1, 0);
  add_imm(jinfo->codebuf, ARM_R2, ARM_R2, bci+CONSTMETHOD_CODEOFFSET);
	  str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R1, ARM_R0, METHOD_FROM_INTERPRETED, 1, 0);
  str_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_BCP, 1, 0);
	  str_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	  Thumb2_Debug(jinfo, H_DEBUG_METHODCALL);
	Thumb2_invoke_save(jinfo, stackdepth);
  sub_imm(jinfo->codebuf, Rstack, Rstack, 4);
	  ldr_imm(jinfo->codebuf, ARM_R3, ARM_R1, 0, 1, 0);
	  mov_reg(jinfo->codebuf, ARM_R2, Rthread);
  str_imm(jinfo->codebuf, Rstack, Ristate, ISTATE_STACK, 1, 0);
add_imm(jinfo->codebuf, ARM_R3, ARM_R3, CODE_ALIGN_SIZE);
//	  enter_leave(jinfo->codebuf, 0);
	  blx_reg(jinfo->codebuf, ARM_R3);
//	  enter_leave(jinfo->codebuf, 1);
  ldr_imm(jinfo->codebuf, Rthread, Ristate, ISTATE_THREAD, 1, 0);
#ifdef USE_RLOCAL
  ldr_imm(jinfo->codebuf, Rlocals, Ristate, ISTATE_LOCALS, 1, 0);
#endif
	  ldr_imm(jinfo->codebuf, Rstack, Rthread, THREAD_JAVA_SP, 1, 0);
	  ldr_imm(jinfo->codebuf, ARM_R2, Ristate, ISTATE_STACK_LIMIT, 1, 0);
	JASSERT(!(bc_stackinfo[bci+len] & BC_COMPILED), "code already compiled for this bytecode?");
	Thumb2_invoke_restore(jinfo, bc_stackinfo[bci+len] & ~BC_FLAGS_MASK);
	  ldr_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_TOP_ZERO_FRAME, 1, 0);
	  add_imm(jinfo->codebuf, ARM_R2, ARM_R2, 4);
	  ldr_imm(jinfo->codebuf, ARM_R3, Rthread, THREAD_PENDING_EXC, 1, 0);
	  str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_JAVA_SP, 1, 0);
	  str_imm(jinfo->codebuf, ARM_R1, Rthread, THREAD_LAST_JAVA_SP, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R3, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION_NO_REGS]);
	}
	break;
      }

      case opc_jsr_w:
      case opc_jsr: {
	Thumb2_Jsr(jinfo , bci, stackdepth);
	break;
      }

      case opc_ret: {
	Thumb2_Exit(jinfo, H_RET, bci, stackdepth);
	break;
      }

      case opc_athrow:
	Thumb2_Exit(jinfo, H_ATHROW, bci, stackdepth);
	break;

      case opc_goto: {
	int offset = GET_JAVA_S2(jinfo->code_base + bci + 1);
	Thumb2_Flush(jinfo);
	bci = Thumb2_Goto(jinfo, bci, offset, len);
	len = 0;
	break;
      }

      case opc_goto_w: {
	int offset = GET_JAVA_U4(jinfo->code_base + bci + 1);
	Thumb2_Flush(jinfo);
	bci = Thumb2_Goto(jinfo, bci, offset, len);
	len = 0;
	break;
      }

      case opc_ifeq:
      case opc_ifne:
      case opc_iflt:
      case opc_ifge:
      case opc_ifgt:
      case opc_ifle:
      case opc_ifnull:
      case opc_ifnonnull: {
	Reg r;
	unsigned cond = opcode - opc_ifeq;
	if (opcode >= opc_ifnull) cond = opcode - opc_ifnull;
	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	cmp_imm(jinfo->codebuf, r, 0);
	bci = Thumb2_Branch(jinfo, bci, cond);
	len = 0;
	break;
      }

      case opc_if_icmpeq:
      case opc_if_icmpne:
      case opc_if_icmplt:
      case opc_if_icmpge:
      case opc_if_icmpgt:
      case opc_if_icmple:
      case opc_if_acmpeq:
      case opc_if_acmpne: {
	Reg r_lho, r_rho;
	unsigned cond = opcode - opc_if_icmpeq;
	if (opcode >= opc_if_acmpeq) cond = opcode - opc_if_acmpeq;
	Thumb2_Fill(jinfo, 2);
	r_rho = POP(jstack);
	r_lho = POP(jstack);
	Thumb2_Flush(jinfo);
	cmp_reg(jinfo->codebuf, r_lho, r_rho);
	bci = Thumb2_Branch(jinfo, bci, cond);
	len = 0;
	break;
      }

      case opc_return:
      case opc_dreturn:
      case opc_lreturn:
      case opc_ireturn:
      case opc_freturn:
      case opc_areturn:
	Thumb2_Return(jinfo, opcode);
	if (!jinfo->compiled_return) jinfo->compiled_return = bci;
	break;

      case opc_return_register_finalizer: {
	Thumb2_Stack *jstack = jinfo->jstack;
	Reg r, r_tmp;
	unsigned loc_eq;

	Thumb2_Flush(jinfo);
	Thumb2_Load(jinfo, 0, stackdepth);
	r = POP(jstack);
	r_tmp = Thumb2_Tmp(jinfo, (1<<r));
	ldr_imm(jinfo->codebuf, r_tmp, r, 4, 1, 0);
	ldr_imm(jinfo->codebuf, r_tmp, r_tmp, KLASS_PART+KLASS_ACCESSFLAGS, 1, 0);
	tst_imm(jinfo->codebuf, r_tmp, JVM_ACC_HAS_FINALIZER);
	loc_eq = forward_16(jinfo->codebuf);
	Thumb2_save_locals(jinfo, stackdepth);
	mov_reg(jinfo->codebuf, ARM_R1, r);
	ldr_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_METHOD, 1, 0);
	ldr_imm(jinfo->codebuf, ARM_R0, ARM_R0, METHOD_CONSTMETHOD, 1, 0);
	add_imm(jinfo->codebuf, ARM_R0, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	str_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
	sub_imm(jinfo->codebuf, ARM_R0, Rstack, 4);
	str_imm(jinfo->codebuf, ARM_R0, Ristate, ISTATE_STACK, 1, 0);

	mov_reg(jinfo->codebuf, ARM_R0, Rthread);
	mov_imm(jinfo->codebuf, ARM_R3, (u32)_ZN18InterpreterRuntime18register_finalizerEP10JavaThreadP7oopDesc);
	blx_reg(jinfo->codebuf, ARM_R3);

	ldr_imm(jinfo->codebuf, ARM_R3, Rthread, THREAD_PENDING_EXC, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R3, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	bcc_patch(jinfo->codebuf, COND_EQ, loc_eq);
	Thumb2_Return(jinfo, opc_return);
	break;
      }

      case opc_new: {
	unsigned loc;

	Thumb2_Flush(jinfo);
	mov_imm(jinfo->codebuf, ARM_R1, GET_JAVA_U2(code_base+bci+1));
	mov_imm(jinfo->codebuf, ARM_R3, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth);
	bl(jinfo->codebuf, handlers[H_NEW]);
      Thumb2_restore_locals(jinfo, stackdepth);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_EQ, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_aastore: {
	Reg src[3], dst[3];
	unsigned loc;

	Thumb2_Fill(jinfo, 3);
	src[0] = POP(jstack);	// value
	src[1] = POP(jstack);	// index
	src[2] = POP(jstack);	// arrayref
	Thumb2_Flush(jinfo);
	dst[0] = ARM_R1;
	dst[1] = ARM_R2;
	dst[2] = ARM_R3;
	mov_multiple(jinfo->codebuf, dst, src, 3);
	mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth - 3);	// 3 args popped above
	bl(jinfo->codebuf, handlers[H_AASTORE]);
      Thumb2_restore_locals(jinfo, stackdepth - 3);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	break;
      }

      case opc_instanceof: {
	unsigned loc;
	Reg r;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R2, r);
	mov_imm(jinfo->codebuf, ARM_R1, GET_JAVA_U2(code_base+bci+1));
	mov_imm(jinfo->codebuf, ARM_R3, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth - 1);
	bl(jinfo->codebuf, handlers[H_INSTANCEOF]);
      Thumb2_restore_locals(jinfo, stackdepth - 1);	// 1 arg popped above
	cmp_imm(jinfo->codebuf, ARM_R0, (unsigned)-1);
	it(jinfo->codebuf, COND_EQ, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_checkcast: {
	unsigned loc;
	Reg r;

	Thumb2_Fill(jinfo, 1);
	r = TOS(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R2, r);
	mov_imm(jinfo->codebuf, ARM_R1, GET_JAVA_U2(code_base+bci+1));
	mov_imm(jinfo->codebuf, ARM_R3, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth);
	bl(jinfo->codebuf, handlers[H_CHECKCAST]);
      Thumb2_restore_locals(jinfo, stackdepth);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_NE, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	break;
      }

      case opc_newarray: {
	Reg r;
	unsigned loc;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R2, r);
	mov_imm(jinfo->codebuf, ARM_R1, code_base[bci+1]);
	mov_imm(jinfo->codebuf, ARM_R3, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth-1);
	bl(jinfo->codebuf, handlers[H_NEWARRAY]);
      Thumb2_restore_locals(jinfo, stackdepth-1);
	ldr_imm(jinfo->codebuf, ARM_R0, Rthread, THREAD_VM_RESULT, 1, 0);
	mov_imm(jinfo->codebuf, ARM_R2, 0);
  	str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_VM_RESULT, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_EQ, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_anewarray: {
	Reg r;
	unsigned loc;

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);
	Thumb2_Flush(jinfo);
	mov_reg(jinfo->codebuf, ARM_R3, r);
	mov_imm(jinfo->codebuf, ARM_R2, GET_JAVA_U2(code_base+bci+1));
	mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
      Thumb2_save_locals(jinfo, stackdepth-1);
	bl(jinfo->codebuf, handlers[H_ANEWARRAY]);
      Thumb2_restore_locals(jinfo, stackdepth-1);
	ldr_imm(jinfo->codebuf, ARM_R0, Rthread, THREAD_VM_RESULT, 1, 0);
	mov_imm(jinfo->codebuf, ARM_R2, 0);
  	str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_VM_RESULT, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_EQ, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_multianewarray: {
	unsigned loc;

	Thumb2_Flush(jinfo);
	mov_imm(jinfo->codebuf, ARM_R0, bci+CONSTMETHOD_CODEOFFSET);
	mov_imm(jinfo->codebuf, ARM_R1, code_base[bci+3] * 4);
      Thumb2_save_locals(jinfo, stackdepth);
	bl(jinfo->codebuf, handlers[H_MULTIANEWARRAY]);
      Thumb2_restore_locals(jinfo, stackdepth - code_base[bci+3]);
	ldr_imm(jinfo->codebuf, ARM_R0, Rthread, THREAD_VM_RESULT, 1, 0);
	mov_imm(jinfo->codebuf, ARM_R2, 0);
  	str_imm(jinfo->codebuf, ARM_R2, Rthread, THREAD_VM_RESULT, 1, 0);
	cmp_imm(jinfo->codebuf, ARM_R0, 0);
	it(jinfo->codebuf, COND_EQ, IT_MASK_T);
	bl(jinfo->codebuf, handlers[H_HANDLE_EXCEPTION]);
	PUSH(jstack, ARM_R0);
	break;
      }

      case opc_arraylength: {
	Reg r_obj, r_len;

	Thumb2_Fill(jinfo, 1);
	r_obj = POP(jstack);
	Thumb2_Spill(jinfo, 1, 0);
	r_len = JSTACK_REG(jstack);
	PUSH(jstack, r_len);
	ldr_imm(jinfo->codebuf, r_len, r_obj, 8, 1, 0);
	break;
      }

      case opc_lookupswitch: {
	unsigned w;
	unsigned nbci;
	int def;
	int npairs;	// The Java spec says signed but must be >= 0??
	unsigned *table, *tablep;
	unsigned r;
	unsigned oldidx;
	unsigned table_loc;
	int i;

	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 4);
	def = bci + (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 8);
	npairs = (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 12);

	Thumb2_Fill(jinfo, 1);
	r = POP(jstack);

	table_loc = out_loc(jinfo->codebuf);
	for (i = 0, tablep = table; i < npairs; i++) {
	  unsigned match;

	  w = tablep[0];
	  match = BYTESEX_REVERSE(w);
	  tablep += 2;
	  cmp_imm(jinfo->codebuf, r, match);
	  t2_bug_align(jinfo->codebuf);
	  forward_32(jinfo->codebuf);
	}
	t2_bug_align(jinfo->codebuf);
	forward_32(jinfo->codebuf);
	Thumb2_codegen(jinfo, bci+len);

	oldidx = codebuf->idx;
	codebuf->idx = table_loc >> 1;
	for (i = 0, tablep = table; i < npairs; i++) {
	  unsigned match;
	  unsigned dest;
	  unsigned loc;

	  w = tablep[0];
	  match = BYTESEX_REVERSE(w);
	  w = tablep[1];
	  dest = bci + (int)BYTESEX_REVERSE(w);
	  tablep += 2;
	  cmp_imm(jinfo->codebuf, r, match);
	  JASSERT(jinfo->bc_stackinfo[dest] & BC_COMPILED, "code not compiled");
	  t2_bug_align(jinfo->codebuf);
	  loc = forward_32(jinfo->codebuf);
	  branch_patch(jinfo->codebuf, COND_EQ, loc, jinfo->bc_stackinfo[dest] & ~BC_FLAGS_MASK);
	}
	JASSERT(jinfo->bc_stackinfo[def] & BC_COMPILED, "default in lookupswitch not compiled");
	t2_bug_align(jinfo->codebuf);
	branch_uncond_patch(jinfo->codebuf, out_loc(jinfo->codebuf), jinfo->bc_stackinfo[def] & ~BC_FLAGS_MASK);
	codebuf->idx = oldidx;

	bci = (unsigned)-1;
	len = 0;

	break;
      }

      case opc_tableswitch: {
	int low, high, i;
	unsigned w;
	unsigned *table, *tablep;
	unsigned nbci;
	int def;
	unsigned loc, table_loc;
	unsigned r, rs;
	unsigned oldidx;
	unsigned negative_offsets, negative_branch_table;

	nbci = bci & ~3;
	w = *(unsigned int *)(code_base + nbci + 8);
	low = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 12);
	high = (int)BYTESEX_REVERSE(w);
	w = *(unsigned int *)(code_base + nbci + 4);
	def = bci + (int)BYTESEX_REVERSE(w);
	table = (unsigned int *)(code_base + nbci + 16);

	Thumb2_Fill(jinfo, 1);
	rs = POP(jstack);
	r = Thumb2_Tmp(jinfo, (1<<rs));
	sub_imm(jinfo->codebuf, r, rs, low);
	cmp_imm(jinfo->codebuf, r, (high-low)+1);
	loc = 0;
	if (jinfo->bc_stackinfo[def] & BC_COMPILED)
	  branch(jinfo->codebuf, COND_CS, jinfo->bc_stackinfo[def] & ~BC_FLAGS_MASK);
	else
	  loc = forward_32(jinfo->codebuf);
	tbh(jinfo->codebuf, ARM_PC, r);
	table_loc = out_loc(jinfo->codebuf);
	negative_offsets = 0;
	for (i = low, tablep = table; i <= high; i++) {
	  int offset;
	  w = *tablep++;
	  offset = (int)BYTESEX_REVERSE(w);
	  if (offset < 0) negative_offsets++;
	  out_16(jinfo->codebuf, 0);
	}
	negative_branch_table = out_loc(jinfo->codebuf);
	for (i = 0; i < (int)negative_offsets; i++) {
	  t2_bug_align(jinfo->codebuf);
	  out_16x2(jinfo->codebuf, 0);
	}

	Thumb2_codegen(jinfo, bci+len);

	if (loc) {
	  JASSERT(jinfo->bc_stackinfo[def] & BC_COMPILED, "def not compiled in tableswitch");
	  branch_patch(jinfo->codebuf, COND_CS, loc, jinfo->bc_stackinfo[def] & ~BC_FLAGS_MASK);
	}

	oldidx = codebuf->idx;
	codebuf->idx = table_loc >> 1;
	for (i = low, tablep = table; i <= high; i++) {
	  unsigned dest;
	  int offset;

	  w = *tablep++;
	  offset = (int)BYTESEX_REVERSE(w);
	  dest = bci + offset;
	  JASSERT(jinfo->bc_stackinfo[dest] & BC_COMPILED, "code not compiled");
	  dest = jinfo->bc_stackinfo[dest] & ~BC_FLAGS_MASK;
	  if (offset < 0) {
	    unsigned oldidx;
	    out_16(jinfo->codebuf, (negative_branch_table >> 1) - (table_loc >> 1));
	    PATCH(negative_branch_table) {
	      t2_bug_align(jinfo->codebuf);
	      branch_uncond_patch(jinfo->codebuf, out_loc(jinfo->codebuf), dest);
	      negative_branch_table = out_loc(jinfo->codebuf);
	    } HCTAP;
	  } else {
	    JASSERT((dest & 1) == 0 && (table_loc & 1) == 0, "unaligned code");
	    offset = (dest >> 1) - (table_loc >> 1);
	    if (offset >= 65536) {
	      longjmp(compiler_error_env, COMPILER_RESULT_FAILED);
	    }
	    out_16(jinfo->codebuf, offset);
	  }
	}
	codebuf->idx = oldidx;
	bci = (unsigned)-1;
	len = 0;
	break;
      }

      case opc_wide: {
	unsigned local = GET_JAVA_U2(code_base + bci + 2);
	opcode = code_base[bci+1];
	if (opcode == opc_iinc) {
	  int constant = GET_JAVA_S2(code_base + bci + 4);
	  unsigned r = jinfo->jregs->r_local[local];
	  
	  if (!r) {
	    int nlocals = jinfo->method->max_locals();
	    r = ARM_IP;
	    stackdepth -= jstack->depth;
	    if (jinfo->method->is_synchronized()) stackdepth += frame::interpreter_frame_monitor_size();
	    load_local(jinfo, r, local, stackdepth);
	    add_imm(jinfo->codebuf, r, r, constant);
	    store_local(jinfo, r, local, stackdepth);
	  } else {
	    Thumb2_Corrupt(jinfo, r, 0);
	    add_imm(jinfo->codebuf, r, r, constant);
	  }
	} else if (opcode == opc_ret) {
	  Thumb2_Exit(jinfo, H_RET, bci, stackdepth);
	} else {
	  if (opcode == opc_iload ||
	  	opcode == opc_fload || opcode == opc_aload)
	    Thumb2_Load(jinfo, local, stackdepth);
	  else if (opcode == opc_lload || opcode == opc_dload)
	    Thumb2_LoadX2(jinfo, local, stackdepth);
	  else if (opcode == opc_istore ||
	  	opcode == opc_fstore || opcode == opc_astore)
	    Thumb2_Store(jinfo, local, stackdepth);
	  else if (opcode == opc_lstore || opcode == opc_dstore)
	    Thumb2_StoreX2(jinfo, local, stackdepth);
	  else fatal1("Undefined wide opcode %d\n", opcode);
	}
	break;
      }

      default:
	JASSERT(0, "unknown bytecode");
	break;
    }
    bci += len;
#ifdef T2EE_PRINT_DISASS
    if (len == 0) {
      if (start_idx == jinfo->codebuf->idx) start_bci[start_idx] = -1;
    } else
      end_bci[start_idx] = bci;
#endif
  }
}

#define BEG_BCI_OFFSET		0
#define END_BCI_OFFSET		1
#define HANDLER_BCI_OFFSET	2
#define KLASS_INDEX_OFFSET	3
#define ENTRY_SIZE		4

extern "C" int Thumb2_lr_to_bci(unsigned lr, methodOop method, Reg *regs, unsigned *locals)
{
  Compiled_Method *cmethod = compiled_method_list;
  typeArrayOop table = method->exception_table();
  constantPoolOop pool = method->constants();
  int length = table->length();

  while (cmethod) {
    unsigned *exception_table = cmethod->exception_table;
    if (exception_table) {
      unsigned code_base = (unsigned)cmethod;
      if (code_base <= lr && lr <= (unsigned)exception_table) {
	int exception_index = -1;
	unsigned exception_found = 0;

	for (int i = 0; i < length; i += ENTRY_SIZE) {
	  unsigned offsets = *exception_table++;
	  unsigned exc_beg = code_base + ((offsets >> 16) << 1);
	  unsigned exc_end = code_base + ((offsets & 0xffff) << 1);

	  if (exc_beg <= lr && lr <= exc_end) {
	    if (exc_beg > exception_found) {
	      // With nested try catch blocks, choose the most deeply nested
	      exception_found = exc_beg;
	      exception_index = i;
	    }	    
	  }
	  if (exception_index >= 0) {
	    if (regs) {
	      for (unsigned i = 0; i < PREGS; i++) {
		int local = cmethod->regusage[i];
		if (local >= 0) {
		  locals[-local] = regs[i];
		}
	      }
	    }
	    return table->int_at(exception_index + BEG_BCI_OFFSET);
	  }
	}
      }
    }
    cmethod = cmethod->next;
  }
  return -1;
}

void Thumb2_generate_exception_table(Compiled_Method *cmethod, Thumb2_Info *jinfo)
{
  methodOop method = jinfo->method;
  typeArrayOop table = method->exception_table();
  constantPoolOop pool = method->constants();
  int length = table->length();
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;

  cmethod->exception_table = (unsigned *)out_pos(jinfo->codebuf);
  for (int i = 0; i < length; i += ENTRY_SIZE) {
    int beg_bci = table->int_at(i + BEG_BCI_OFFSET);
    int end_bci = table->int_at(i + END_BCI_OFFSET);
    unsigned stackinfo;
    unsigned beg_offset, end_offset;

    stackinfo = bc_stackinfo[beg_bci];
    beg_offset = (stackinfo & ~BC_FLAGS_MASK) >> 1;
    stackinfo = bc_stackinfo[end_bci];
    end_offset = (stackinfo & ~BC_FLAGS_MASK) >> 1;
    if (!(beg_offset != 0 && end_offset >= beg_offset && end_offset < 65536)) {
	longjmp(compiler_error_env, COMPILER_RESULT_FAILED);
    }
    out_32(jinfo->codebuf, (beg_offset << 16) | (end_offset));
  }
}

void Thumb2_tablegen(Compiled_Method *cmethod, Thumb2_Info *jinfo)
{
  unsigned code_size = jinfo->code_size;
  jubyte *code_base = jinfo->code_base;
  unsigned *bc_stackinfo = jinfo->bc_stackinfo;
  unsigned bci;
  unsigned count = 0;
  unsigned i;
  CodeBuf *codebuf = jinfo->codebuf;

  cmethod->osr_table = (unsigned *)out_pos(jinfo->codebuf);
  out_32(codebuf, 0);
  bc_stackinfo[0] |= BC_BACK_TARGET;
  for (bci = 0; bci < code_size;) {
    unsigned stackinfo = bc_stackinfo[bci];
    unsigned bytecodeinfo;
    unsigned opcode;

    if (stackinfo & BC_BACK_TARGET) {
      unsigned code_offset = (stackinfo & ~BC_FLAGS_MASK) >> 1;
      JASSERT(stackinfo & BC_COMPILED, "back branch target not compiled???");
      if (code_offset >= 65536) {
	longjmp(compiler_error_env, COMPILER_RESULT_FAILED);
      }
//      JASSERT(code_offset < (1<<16), "oops, codesize too big");
      out_32(codebuf, (bci << 16) | code_offset);
      count++;
    }

    opcode = code_base[bci];
    bytecodeinfo = bcinfo[opcode];
    if (!BCI_SPECIAL(bytecodeinfo)) {
      bci += BCI_LEN(bytecodeinfo);
      continue;
    } else {
      int len = Bytecodes::length_for((Bytecodes::Code)opcode);
      if (len <= 0) len = Bytecodes::special_length_at((address)(code_base+bci), (address)(code_base+code_size));
      bci += len;
    }
  }
  *cmethod->osr_table = count;
  if (jinfo->method->has_exception_handler())
    Thumb2_generate_exception_table(cmethod, jinfo);
}

extern "C" void Thumb2_Clear_Cache(char *base, char *limit);
#define IS_COMPILED(e, cb) ((e) >= (unsigned)(cb) && (e) < (unsigned)(cb) + (cb)->size)

unsigned Thumb2_osr_from_bci(Compiled_Method *cmethod, unsigned bci)
{
  unsigned *osr_table;
  unsigned count;
  unsigned i;

  osr_table = cmethod->osr_table;
  if (!osr_table) return 0;
  count = *osr_table++;
  for (i = 0; i < count; i++) {
    unsigned u = *osr_table++;

    if (bci == (u>>16)) return (u & 0xffff) << 1;
  }
  return 0;
}

static int DebugSwitch = 1;

extern "C" void Debug_Ignore_Safepoints(void)
{
	printf("Ignore Safepoints\n");
}

extern "C" void Debug_Notice_Safepoints(void)
{
	printf("Notice Safepoints\n");
}

extern "C" void Debug_ExceptionReturn(interpreterState istate, intptr_t *stack)
{
  JavaThread *thread = istate->thread();

  if (thread->has_pending_exception()) {
    Handle ex(thread, thread->pending_exception());
    tty->print_cr("Exception %s", Klass::cast(ex->klass())->external_name());
  }
}

extern "C" void Debug_Stack(intptr_t *stack)
{
  int i;
  char msg[16];

  tty->print("  Stack:");
  for (i = 0; i < 6; i++) {
    tty->print(" [");
    sprintf(msg, "%d", i);
    tty->print(msg);
    tty->print("] = ");
    sprintf(msg, "%08x", (int)stack[i]);
    tty->print(msg);
  }
  tty->cr();
}

extern "C" void Debug_MethodEntry(interpreterState istate, intptr_t *stack, methodOop callee)
{
#if 0
  if (DebugSwitch) {
    methodOop method = istate->method();
    tty->print("Entering ");
    callee->print_short_name(tty);
    tty->print(" from ");
    method->print_short_name(tty);
    tty->cr();
    Debug_Stack(stack);
    tty->flush();
  }
#endif
}

extern "C" void Debug_MethodExit(interpreterState istate, intptr_t *stack)
{
  if (DebugSwitch) {
    methodOop method = istate->method();
    JavaThread *thread = istate->thread();
    oop exc = thread->pending_exception();

    if (!exc) return;
    tty->print("Leaving ");
    method->print_short_name(tty);
    tty->cr();
    Debug_Stack(stack);
    tty->flush();
    if (exc) tty->print_cr("Exception %s", exc->print_value_string());
  }
}

extern "C" void Debug_MethodCall(interpreterState istate, intptr_t *stack, methodOop callee)
{
#if 0
  if (DebugSwitch) {
    methodOop method = istate->method();
    tty->print("Calling ");
    callee->print_short_name(tty);
    tty->print(" from ");
    method->print_short_name(tty);
    tty->cr();
    Debug_Stack(stack);
    tty->flush();
  }
#endif
}

extern "C" int Debug_irem_Handler(int a, int b)
{
	printf("%d %% %d\n", a, b);
	return a%b;
}

extern "C" void Thumb2_Install(methodOop mh, u32 entry);

#define IS_COMPILED(e, cb) ((e) >= (unsigned)(cb) && (e) < (unsigned)(cb) + (cb)->size)

extern "C" unsigned cmpxchg_ptr(unsigned new_value, volatile unsigned *ptr, unsigned cmp_value);
static volatile unsigned compiling;
static unsigned CompileCount = 0;
static unsigned MaxCompile = 130;

#define COMPILE_ONLY	0
#define COMPILE_COUNT	0
#define DISASS_AFTER	0
//#define COMPILE_LIST	0

#ifdef COMPILE_LIST
static const char *compile_list[] = {
	0
};
#endif

static unsigned compiled_methods = 0;

#ifdef T2EE_PRINT_STATISTICS
static unsigned bytecodes_compiled = 0;
static unsigned arm_code_generated = 0;
static unsigned total_zombie_bytes = 0;
static clock_t total_compile_time = 0;
#endif

extern unsigned CPUInfo;
static int DisableCompiler = 0;

extern "C" unsigned long long Thumb2_Compile(JavaThread *thread, unsigned branch_pc)
{
  HandleMark __hm(thread);
  frame fr = thread->last_frame();
  methodOop method = fr.interpreter_frame_method();
  symbolOop name = method->name();
  symbolOop sig = method->signature();
  jbyte *base = sig->base();;

  jubyte *code_base = (jubyte *)method->code_base();
  int code_size = method->code_size();
  InvocationCounter* ic = method->invocation_counter();
  InvocationCounter* bc = method->backedge_counter();
  Thumb2_Info jinfo_str;
  CodeBuf codebuf_str;
  Thumb2_Stack jstack_str;
  Thumb2_Registers jregs_str;
  int idx;
  u32 code_handle, slow_entry;
  Thumb2_CodeBuf *cb = thumb2_codebuf;
  int rc;
  char *saved_hp;
  Compiled_Method *cmethod;
  u32 compiled_offset;
  Thumb2_Entrypoint thumb_entry;
  int compiled_accessor;

  if (DisableCompiler || method->is_not_compilable()) {
	ic->set(ic->state(), 1);
	bc->set(ic->state(), 1);
	return 0;
  }

  slow_entry = *(unsigned *)method->from_interpreted_entry();
  if (IS_COMPILED(slow_entry, cb)) {
    cmethod = (Compiled_Method *)(slow_entry & ~TBIT);
    compiled_offset = Thumb2_osr_from_bci(cmethod, branch_pc);
    if (compiled_offset == 0) return 0;
    thumb_entry.compiled_entrypoint = slow_entry + compiled_offset;
    thumb_entry.osr_entry = (unsigned)cmethod->osr_entry | TBIT;
    return *(unsigned long long *)&thumb_entry;
  }

  ic->decay();
  bc->decay();

  // Dont compile anything with code size >= 32K.
  // We rely on the bytecode index fitting in 16 bits
  //
  // Dont compile anything with max stack + maxlocal > 1K
  // The range of an LDR in T2 is -4092..4092
  // Othersize we have difficulty access the locals from the stack pointer
  //
  if (code_size > THUMB2_MAX_BYTECODE_SIZE ||
		(method->max_locals() + method->max_stack()) >= 1000 ||
		method->has_monitor_bytecodes()) {
        method->set_not_compilable();
	return 0;
  }

  if (COMPILE_COUNT && compiled_methods == COMPILE_COUNT) return 0;

  if (COMPILE_ONLY) {
    if (strcmp(name->as_C_string(), COMPILE_ONLY) != 0) return 0;
  }

#ifdef COMPILE_LIST
  {
	const char **argv = compile_list;
	const char *s;
	while (s = *argv++) {
		if (strcmp(s, method->name_and_sig_as_C_string()) == 0)
			break;
	}
	if (!s) return 0;
  }
#endif

  saved_hp = cb->hp;
  if (rc = setjmp(compiler_error_env)) {
    cb->hp = saved_hp;
    if (rc == COMPILER_RESULT_FAILED)
        method->set_not_compilable();
    if (rc == COMPILER_RESULT_FATAL)
	DisableCompiler = 1;
    compiling = 0;
    return 0;
  }

  if (cmpxchg_ptr(1, &compiling, 0)) return 0;

#ifdef T2EE_PRINT_STATISTICS
  clock_t compile_time = clock();
#endif

#ifdef T2EE_PRINT_COMPILATION
  if (t2ee_print_compilation) {
    fprintf(stderr, "Compiling %d %c%c %s\n",
	compiled_methods,
	method->is_synchronized() ? 'S' : ' ',
	method->has_exception_handler() ? 'E' : ' ',
	method->name_and_sig_as_C_string());
  }
#endif

  memset(bc_stackinfo, 0, code_size * sizeof(unsigned));
  memset(locals_info, 0, method->max_locals() * sizeof(unsigned));
#ifdef T2EE_PRINT_DISASS
  memset(start_bci, 0xff, sizeof(start_bci));
  memset(end_bci, 0xff, sizeof(end_bci));
#endif

  jinfo_str.thread = thread;
  jinfo_str.method = method;
  jinfo_str.code_base = code_base;
  jinfo_str.code_size = code_size;
  jinfo_str.bc_stackinfo = bc_stackinfo;
  jinfo_str.locals_info = locals_info;
  jinfo_str.compiled_return = 0;
  jinfo_str.zombie_bytes = 0;
  jinfo_str.is_leaf = 1;

  Thumb2_local_info_from_sig(&jinfo_str, method, base);

  Thumb2_pass1(&jinfo_str, 0);
  Thumb2_pass2(&jinfo_str, 0, 0);

  codebuf_str.codebuf = (unsigned short *)cb->hp;
  codebuf_str.idx = 0;
  codebuf_str.limit = (unsigned short *)cb->sp - (unsigned short *)cb->hp;

  jstack_str.stack = stack;
  jstack_str.depth = 0;

  memset(r_local, 0, method->max_locals() * sizeof(unsigned));

  jregs_str.r_local = r_local;

  jinfo_str.codebuf = &codebuf_str;
  jinfo_str.jstack = &jstack_str;
  jinfo_str.jregs = &jregs_str;

  jregs_str.pregs[0] = JAZ_V1;
  jregs_str.pregs[1] = JAZ_V2;
  jregs_str.pregs[2] = JAZ_V3;
  jregs_str.pregs[3] = JAZ_V4;

#ifndef USE_RLOCAL
  jregs_str.pregs[4] = JAZ_V5;
#endif

  jregs_str.npregs = PREGS;

  Thumb2_RegAlloc(&jinfo_str);

  slow_entry = out_align(&codebuf_str, CODE_ALIGN);
  cmethod = (Compiled_Method *)slow_entry;
  slow_entry |= TBIT;

  cb->hp += codebuf_str.idx * 2;
  codebuf_str.codebuf = (unsigned short *)cb->hp;
  codebuf_str.idx = 0;
  codebuf_str.limit = (unsigned short *)cb->sp - (unsigned short *)cb->hp;

  compiled_accessor = 1;
  if (!method->is_accessor() || !Thumb2_Accessor(&jinfo_str)) {
    Thumb2_Enter(&jinfo_str);
    Thumb2_codegen(&jinfo_str, 0);
    compiled_accessor = 0;
  }

#ifdef T2EE_PRINT_DISASS
  if (DISASS_AFTER == 0 || compiled_methods >= DISASS_AFTER)
    if (t2ee_print_disass)
	Thumb2_disass(&jinfo_str);
#endif

  for (int i = 0; i < PREGS; i++)
    cmethod->regusage[i] = jregs_str.mapping[i];

  Thumb2_Clear_Cache(cb->hp, cb->hp + codebuf_str.idx * 2);

#ifdef T2EE_PRINT_STATISTICS
  compile_time = clock() - compile_time;
  total_compile_time += compile_time;

  if (t2ee_print_statistics) {
    unsigned codegen = codebuf_str.idx * 2;
    bytecodes_compiled += code_size;
    arm_code_generated += codegen;
    total_zombie_bytes += jinfo_str.zombie_bytes;
    fprintf(stderr, "%d bytecodes => %d bytes code in %.2f sec, totals: %d => %d in %.2f sec\n",
      code_size, codegen, (double)compile_time/(double)CLOCKS_PER_SEC,
    bytecodes_compiled, arm_code_generated, (double)total_compile_time/(double)CLOCKS_PER_SEC);
  }
#endif

  code_handle = out_align(&codebuf_str, sizeof(address));

  out_32(&codebuf_str, slow_entry);

  if (!compiled_accessor)
    Thumb2_tablegen(cmethod, &jinfo_str);

  cb->hp += codebuf_str.idx * 2;

  *compiled_method_list_tail_ptr = cmethod;
  compiled_method_list_tail_ptr = &(cmethod->next);

  Thumb2_Install(method, code_handle);

  compiled_methods++;

  compiling = 0;

  compiled_offset = Thumb2_osr_from_bci(cmethod, branch_pc);
  if (compiled_offset == 0) return 0;
  thumb_entry.compiled_entrypoint = slow_entry + compiled_offset;
  thumb_entry.osr_entry = (unsigned)cmethod->osr_entry | TBIT;
  return *(unsigned long long *)&thumb_entry;
}

extern "C" void Thumb2_DivZero_Handler(void);
extern "C" void Thumb2_ArrayBounds_Handler(void);
extern "C" void Thumb2_Handle_Exception(void);
extern "C" void Thumb2_Handle_Exception_NoRegs(void);
extern "C" void Thumb2_Exit_To_Interpreter(void);
extern "C" void Thumb2_Stack_Overflow(void);

extern "C" void __divsi3(void);
extern "C" void __aeabi_ldivmod(void);
extern "C" void __aeabi_i2f(void);
extern "C" void __aeabi_i2d(void);
extern "C" void __aeabi_l2f(void);
extern "C" void __aeabi_l2d(void);
extern "C" void __aeabi_f2d(void);
extern "C" void __aeabi_d2f(void);
extern "C" void Helper_new(void);
extern "C" void Helper_instanceof(void);
extern "C" void Helper_checkcast(void);
extern "C" void Helper_aastore(void);
extern "C" void Helper_aputfield(void);
extern "C" void Helper_synchronized_enter(void);
extern "C" void Helper_synchronized_exit(void);

extern "C" void _ZN13SharedRuntime3f2iEf(void);
extern "C" void _ZN13SharedRuntime3f2lEf(void);
extern "C" void _ZN13SharedRuntime3d2iEd(void);
extern "C" void _ZN13SharedRuntime3d2lEd(void);
extern "C" void _ZN18InterpreterRuntime8newarrayEP10JavaThread9BasicTypei(void);
extern "C" void _ZN18InterpreterRuntime9anewarrayEP10JavaThreadP19constantPoolOopDescii(void);
extern "C" void _ZN18InterpreterRuntime14multianewarrayEP10JavaThreadPi(void);
extern "C" void _ZN18InterpreterRuntime3ldcEP10JavaThreadb(void);

extern char Thumb2_stubs[];
extern char Thumb2_stubs_end[];
extern char Thumb2_idiv_stub[];
extern char Thumb2_irem_stub[];
extern char Thumb2_invokeinterface_stub[];
extern char Thumb2_invokevirtual_stub[];
extern char Thumb2_invokestatic_stub[];
extern char Thumb2_invokespecial_stub[];
extern char Thumb2_getfield_word_stub[];
extern char Thumb2_getfield_sh_stub[];
extern char Thumb2_getfield_h_stub[];
extern char Thumb2_getfield_sb_stub[];
extern char Thumb2_getfield_dw_stub[];
extern char Thumb2_putfield_word_stub[];
extern char Thumb2_putfield_h_stub[];
extern char Thumb2_putfield_b_stub[];
extern char Thumb2_putfield_a_stub[];
extern char Thumb2_putfield_dw_stub[];
extern char Thumb2_getstatic_word_stub[];
extern char Thumb2_getstatic_sh_stub[];
extern char Thumb2_getstatic_h_stub[];
extern char Thumb2_getstatic_sb_stub[];
extern char Thumb2_getstatic_dw_stub[];
extern char Thumb2_putstatic_word_stub[];
extern char Thumb2_putstatic_h_stub[];
extern char Thumb2_putstatic_b_stub[];
extern char Thumb2_putstatic_a_stub[];
extern char Thumb2_putstatic_dw_stub[];

#define STUBS_SIZE	(Thumb2_stubs_end-Thumb2_stubs)
#define IDIV_STUB		(Thumb2_idiv_stub-Thumb2_stubs)
#define IREM_STUB		(Thumb2_irem_stub-Thumb2_stubs)
#define INVOKEINTERFACE_STUB	(Thumb2_invokeinterface_stub-Thumb2_stubs)
#define INVOKEVIRTUAL_STUB	(Thumb2_invokevirtual_stub-Thumb2_stubs)
#define INVOKESTATIC_STUB	(Thumb2_invokestatic_stub-Thumb2_stubs)
#define INVOKESPECIAL_STUB	(Thumb2_invokespecial_stub-Thumb2_stubs)
#define GETFIELD_WORD_STUB	(Thumb2_getfield_word_stub-Thumb2_stubs)
#define GETFIELD_SH_STUB	(Thumb2_getfield_sh_stub-Thumb2_stubs)
#define GETFIELD_H_STUB		(Thumb2_getfield_h_stub-Thumb2_stubs)
#define GETFIELD_SB_STUB	(Thumb2_getfield_sb_stub-Thumb2_stubs)
#define GETFIELD_DW_STUB	(Thumb2_getfield_dw_stub-Thumb2_stubs)
#define PUTFIELD_WORD_STUB	(Thumb2_putfield_word_stub-Thumb2_stubs)
#define PUTFIELD_H_STUB		(Thumb2_putfield_h_stub-Thumb2_stubs)
#define PUTFIELD_B_STUB		(Thumb2_putfield_b_stub-Thumb2_stubs)
#define PUTFIELD_A_STUB		(Thumb2_putfield_a_stub-Thumb2_stubs)
#define PUTFIELD_DW_STUB	(Thumb2_putfield_dw_stub-Thumb2_stubs)
#define GETSTATIC_WORD_STUB	(Thumb2_getstatic_word_stub-Thumb2_stubs)
#define GETSTATIC_SH_STUB	(Thumb2_getstatic_sh_stub-Thumb2_stubs)
#define GETSTATIC_H_STUB	(Thumb2_getstatic_h_stub-Thumb2_stubs)
#define GETSTATIC_SB_STUB	(Thumb2_getstatic_sb_stub-Thumb2_stubs)
#define GETSTATIC_DW_STUB	(Thumb2_getstatic_dw_stub-Thumb2_stubs)
#define PUTSTATIC_WORD_STUB	(Thumb2_putstatic_word_stub-Thumb2_stubs)
#define PUTSTATIC_H_STUB	(Thumb2_putstatic_h_stub-Thumb2_stubs)
#define PUTSTATIC_B_STUB	(Thumb2_putstatic_b_stub-Thumb2_stubs)
#define PUTSTATIC_A_STUB	(Thumb2_putstatic_a_stub-Thumb2_stubs)
#define PUTSTATIC_DW_STUB	(Thumb2_putstatic_dw_stub-Thumb2_stubs)

extern "C" void Thumb2_NullPtr_Handler(void);


extern "C" int Thumb2_Check_Null(unsigned *regs, unsigned pc)
{
  Thumb2_CodeBuf *cb = thumb2_codebuf;
  if (!(CPUInfo & ARCH_THUMBEE)) return 0;
  if (IS_COMPILED(pc, cb)) {
    regs[ARM_LR] = pc;
    regs[ARM_PC] = (unsigned)Thumb2_NullPtr_Handler;
    regs[ARM_CPSR] &= ~CPSR_THUMB_BIT;
    return 1;
  }
  return 0;
}

extern "C" void Thumb2_Initialize(void)
{
  CodeBuf codebuf;
  Thumb2_CodeBuf *cb;
  u32 h_divzero;
  u32 loc_irem, loc_idiv, loc_ldiv;
  int rc;

  if (!(CPUInfo & ARCH_THUMBEE)) {
    DisableCompiler = 1;
    return;
  }

#ifdef T2EE_PRINT_COMPILATION
  t2ee_print_compilation = getenv("T2EE_PRINT_COMPILATION");
#endif
#ifdef T2EE_PRINT_STATISTICS
  t2ee_print_statistics = getenv("T2EE_PRINT_STATISTICS");
#endif
#ifdef T2EE_PRINT_DISASS
  t2ee_print_disass = getenv("T2EE_PRINT_DISASS");
#endif
#ifdef T2EE_PRINT_REGUSAGE
  t2ee_print_regusage = getenv("T2EE_PRINT_REGUSAGE");
#endif

  cb = (Thumb2_CodeBuf *)mmap(0, THUMB2_CODEBUF_SIZE, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
  if (cb == MAP_FAILED) {
    DisableCompiler = 1;
    return;
  }

  cb->size = THUMB2_CODEBUF_SIZE;
  cb->hp = (char *)cb + sizeof(Thumb2_CodeBuf);
  cb->sp = (char *)cb + THUMB2_CODEBUF_SIZE;

  codebuf.codebuf = (unsigned short *)cb->hp;
  codebuf.idx = 0;
  codebuf.limit = (unsigned short *)cb->sp - (unsigned short *)cb->hp;

  if (rc = setjmp(compiler_error_env)) {
    DisableCompiler = 1;
    return;
  }

#if 1
  memcpy(cb->hp, Thumb2_stubs, STUBS_SIZE);

  handlers[H_IDIV] = (unsigned)(cb->hp + IDIV_STUB);
  handlers[H_IREM] = (unsigned)(cb->hp + IREM_STUB);
  handlers[H_INVOKEINTERFACE] = (unsigned)(cb->hp + INVOKEINTERFACE_STUB);
  handlers[H_INVOKEVIRTUAL] = (unsigned)(cb->hp + INVOKEVIRTUAL_STUB);
  handlers[H_INVOKESTATIC] = (unsigned)(cb->hp + INVOKESTATIC_STUB);
  handlers[H_INVOKESPECIAL] = (unsigned)(cb->hp + INVOKESPECIAL_STUB);

  handlers[H_GETFIELD_WORD] = (unsigned)(cb->hp + GETFIELD_WORD_STUB);
  handlers[H_GETFIELD_SH] = (unsigned)(cb->hp + GETFIELD_SH_STUB);
  handlers[H_GETFIELD_H] = (unsigned)(cb->hp + GETFIELD_H_STUB);
  handlers[H_GETFIELD_SB] = (unsigned)(cb->hp + GETFIELD_SB_STUB);
  handlers[H_GETFIELD_DW] = (unsigned)(cb->hp + GETFIELD_DW_STUB);

  handlers[H_PUTFIELD_WORD] = (unsigned)(cb->hp + PUTFIELD_WORD_STUB);
  handlers[H_PUTFIELD_H] = (unsigned)(cb->hp + PUTFIELD_H_STUB);
  handlers[H_PUTFIELD_B] = (unsigned)(cb->hp + PUTFIELD_B_STUB);
  handlers[H_PUTFIELD_A] = (unsigned)(cb->hp + PUTFIELD_A_STUB);
  handlers[H_PUTFIELD_DW] = (unsigned)(cb->hp + PUTFIELD_DW_STUB);

  handlers[H_GETSTATIC_WORD] = (unsigned)(cb->hp + GETSTATIC_WORD_STUB);
  handlers[H_GETSTATIC_SH] = (unsigned)(cb->hp + GETSTATIC_SH_STUB);
  handlers[H_GETSTATIC_H] = (unsigned)(cb->hp + GETSTATIC_H_STUB);
  handlers[H_GETSTATIC_SB] = (unsigned)(cb->hp + GETSTATIC_SB_STUB);
  handlers[H_GETSTATIC_DW] = (unsigned)(cb->hp + GETSTATIC_DW_STUB);

  handlers[H_PUTSTATIC_WORD] = (unsigned)(cb->hp + PUTSTATIC_WORD_STUB);
  handlers[H_PUTSTATIC_H] = (unsigned)(cb->hp + PUTSTATIC_H_STUB);
  handlers[H_PUTSTATIC_B] = (unsigned)(cb->hp + PUTSTATIC_B_STUB);
  handlers[H_PUTSTATIC_A] = (unsigned)(cb->hp + PUTSTATIC_A_STUB);
  handlers[H_PUTSTATIC_DW] = (unsigned)(cb->hp + PUTSTATIC_DW_STUB);

  codebuf.idx += (Thumb2_stubs_end-Thumb2_stubs) >> 1;
#endif

  handlers[H_LDIV] = handlers[H_LREM] = out_pos(&codebuf);
  dop_reg(&codebuf, DP_ORR, ARM_IP, ARM_R2, ARM_R3, 0, 0);
  loc_ldiv = forward_16(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_ldivmod);
  mov_reg(&codebuf, ARM_PC, ARM_IP);
  bcc_patch(&codebuf, COND_EQ, loc_ldiv);
  mov_imm(&codebuf, ARM_IP, (u32)Thumb2_DivZero_Handler);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_ARRAYBOUND] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)Thumb2_ArrayBounds_Handler);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  handlers[H_HANDLE_EXCEPTION] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)Thumb2_Handle_Exception);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  handlers[H_HANDLE_EXCEPTION_NO_REGS] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)Thumb2_Handle_Exception_NoRegs);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  handlers[H_STACK_OVERFLOW] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)Thumb2_Stack_Overflow);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  handlers[H_DREM] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)fmod);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_FREM] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)fmodf);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  handlers[H_I2F] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_i2f);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_I2D] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_i2d);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_L2F] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_l2f);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_L2D] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_l2d);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_F2I] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN13SharedRuntime3f2iEf);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_F2L] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN13SharedRuntime3f2lEf);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_F2D] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_f2d);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_D2I] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN13SharedRuntime3d2iEd);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_D2L] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN13SharedRuntime3d2lEd);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

  handlers[H_D2F] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_IP, (u32)__aeabi_d2f);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// NEW Stub
//   r1 = index
//   r3 = bci
//   result -> R0, == 0 => exception
  handlers[H_NEW] = out_pos(&codebuf);
  mov_reg(&codebuf, ARM_R0, Ristate);
  ldr_imm(&codebuf, ARM_R2, ARM_R0, ISTATE_METHOD, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_new);
  ldr_imm(&codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_R2, ARM_R2, ARM_R3);
sub_imm(&codebuf, ARM_R3, Rstack, 4);
  str_imm(&codebuf, ARM_R3, ARM_R0, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_R2, ARM_R0, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// NEWARRAY Stub
//   r1 = atype
//   r2 = tos
//   r3 = bci
//   result -> thread->vm_result
  handlers[H_NEWARRAY] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R0, Ristate, ISTATE_METHOD, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN18InterpreterRuntime8newarrayEP10JavaThread9BasicTypei);
  ldr_imm(&codebuf, ARM_R0, ARM_R0, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_R3, ARM_R0, ARM_R3);
  mov_reg(&codebuf, ARM_R0, Rthread);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_BCP, 1, 0);
sub_imm(&codebuf, ARM_R3, Rstack, 4);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_STACK, 1, 0);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// ANEWARRAY Stub
//   r0 = bci
//   r2 = index
//   r3 = tos
//   result -> thread->vm_result
  handlers[H_ANEWARRAY] = out_pos(&codebuf);
sub_imm(&codebuf, ARM_R1, Rstack, 4);
  str_imm(&codebuf, ARM_R1, Ristate, ISTATE_STACK, 1, 0);
  ldr_imm(&codebuf, ARM_R1, Ristate, ISTATE_METHOD, 1, 0);
  ldr_imm(&codebuf, ARM_IP, ARM_R1, METHOD_CONSTMETHOD, 1, 0);
  ldr_imm(&codebuf, ARM_R1, ARM_R1, METHOD_CONSTANTS, 1, 0);
  add_reg(&codebuf, ARM_R0, ARM_IP, ARM_R0);
  mov_imm(&codebuf, ARM_IP, (u32)_ZN18InterpreterRuntime9anewarrayEP10JavaThreadP19constantPoolOopDescii);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_R0, Rthread);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// MULTIANEWARRAY Stub
//   r0 = bci
//   r1 = dimensions (*4)
  handlers[H_MULTIANEWARRAY] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R2, Ristate, ISTATE_METHOD, 1, 0);
  sub_imm(&codebuf, ARM_R3, Rstack, 4);
  ldr_imm(&codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_STACK, 1, 0);
  add_reg(&codebuf, ARM_R0, ARM_R2, ARM_R0);
  add_reg(&codebuf, Rstack, Rstack, ARM_R1);
  mov_imm(&codebuf, ARM_R3, (u32)_ZN18InterpreterRuntime14multianewarrayEP10JavaThreadPi);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_R0, Rthread);
  sub_imm(&codebuf, ARM_R1, Rstack, 4);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

// LDC Stub
//   r0 = bci
  handlers[H_LDC] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R2, Ristate, ISTATE_METHOD, 1, 0);
  sub_imm(&codebuf, ARM_R3, Rstack, 4);
  ldr_imm(&codebuf, ARM_R2, ARM_R2, METHOD_CONSTMETHOD, 1, 0);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_STACK, 1, 0);
  add_reg(&codebuf, ARM_R0, ARM_R2, ARM_R0);
  mov_imm(&codebuf, ARM_R3, (u32)_ZN18InterpreterRuntime3ldcEP10JavaThreadb);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_R0, Rthread);
//  mov_imm(&codebuf, ARM_R1, 0);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

// INSTANCEOF Stub
//   r1 = index
//   r3 = bci
//   result -> R0, == -1 => exception
  handlers[H_INSTANCEOF] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R0, Ristate, ISTATE_METHOD, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_instanceof);
  ldr_imm(&codebuf, ARM_R0, ARM_R0, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_R0, ARM_R0, ARM_R3);
sub_imm(&codebuf, ARM_R3, Rstack, 4);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_R0, Ristate);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// CHECKCAST Stub
//   r1 = index
//   r3 = bci
//   result -> R0, != 0 => exception
  handlers[H_CHECKCAST] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R0, Ristate, ISTATE_METHOD, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_checkcast);
  ldr_imm(&codebuf, ARM_R0, ARM_R0, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_R0, ARM_R0, ARM_R3);
sub_imm(&codebuf, ARM_R3, Rstack, 4);
  str_imm(&codebuf, ARM_R3, Ristate, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_BCP, 1, 0);
  mov_reg(&codebuf, ARM_R0, Ristate);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// AASTORE Stub
//   r0 = bci
//   r1 = value
//   r2 = index
//   r3 = arrayref
  handlers[H_AASTORE] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_IP, Ristate, ISTATE_METHOD, 1, 0);
  ldr_imm(&codebuf, ARM_IP, ARM_IP, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_IP, ARM_IP, ARM_R0);
sub_imm(&codebuf, ARM_R0, Rstack, 4);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_IP, Ristate, ISTATE_BCP, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_aastore);
  mov_reg(&codebuf, ARM_R0, Ristate);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

// APUTFIELD Stub
//   r0 = obj
  handlers[H_APUTFIELD] = out_pos(&codebuf);
  mov_imm(&codebuf, ARM_R3, (u32)Helper_aputfield);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

// SYNCHRONIZED_ENTER Stub
//   r0 = bci
//   r1 = monitor
  handlers[H_SYNCHRONIZED_ENTER] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_IP, Ristate, ISTATE_METHOD, 1, 0);
  ldr_imm(&codebuf, ARM_IP, ARM_IP, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_IP, ARM_IP, ARM_R0);
sub_imm(&codebuf, ARM_R0, Rstack, 4);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_IP, Ristate, ISTATE_BCP, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_synchronized_enter);
  mov_reg(&codebuf, ARM_R0, Rthread);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

//
// SYNCHRONIZED_EXIT Stub
//   r0 = bci
//   r1 = monitor
  handlers[H_SYNCHRONIZED_EXIT] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_IP, Ristate, ISTATE_METHOD, 1, 0);
  ldr_imm(&codebuf, ARM_IP, ARM_IP, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, ARM_IP, ARM_IP, ARM_R0);
sub_imm(&codebuf, ARM_R0, Rstack, 4);
  str_imm(&codebuf, ARM_R0, Ristate, ISTATE_STACK, 1, 0);
  str_imm(&codebuf, ARM_IP, Ristate, ISTATE_BCP, 1, 0);
  mov_imm(&codebuf, ARM_IP, (u32)Helper_synchronized_exit);
  mov_reg(&codebuf, ARM_R0, Rthread);
  mov_reg(&codebuf, ARM_PC, ARM_IP);

#define DEBUG_REGSET ((1<<ARM_R0)|(1<<ARM_R1)|(1<<ARM_R2)|(1<<ARM_R3)|(1<<ARM_IP))

// DEBUG_METHODENTRY
  handlers[H_DEBUG_METHODENTRY] = out_pos(&codebuf);
  stm(&codebuf, DEBUG_REGSET | (1<<ARM_LR), ARM_SP, PUSH_FD, 1);
  mov_reg(&codebuf, ARM_R2, ARM_R0);
  mov_reg(&codebuf, ARM_R0, ARM_R8);
  mov_reg(&codebuf, ARM_R1, ARM_R4);
  mov_imm(&codebuf, ARM_IP, (u32)Debug_MethodEntry);
  blx_reg(&codebuf, ARM_IP);
  ldm(&codebuf, DEBUG_REGSET | (1<<ARM_PC), ARM_SP, POP_FD, 1);

// DEBUG_METHODEXIT
  handlers[H_DEBUG_METHODEXIT] = out_pos(&codebuf);
  stm(&codebuf, DEBUG_REGSET | (1<<ARM_LR), ARM_SP, PUSH_FD, 1);
  mov_reg(&codebuf, ARM_R0, ARM_R8);
  mov_reg(&codebuf, ARM_R1, ARM_R4);
  mov_imm(&codebuf, ARM_IP, (u32)Debug_MethodExit);
  blx_reg(&codebuf, ARM_IP);
  ldm(&codebuf, DEBUG_REGSET | (1<<ARM_PC), ARM_SP, POP_FD, 1);

// DEBUG_METHODCALL
  handlers[H_DEBUG_METHODCALL] = out_pos(&codebuf);
  stm(&codebuf, DEBUG_REGSET | (1<<ARM_LR), ARM_SP, PUSH_FD, 1);
  mov_reg(&codebuf, ARM_R2, ARM_R0);
  mov_reg(&codebuf, ARM_R0, ARM_R8);
  mov_reg(&codebuf, ARM_R1, ARM_R4);
  mov_imm(&codebuf, ARM_IP, (u32)Debug_MethodCall);
  blx_reg(&codebuf, ARM_IP);
  ldm(&codebuf, DEBUG_REGSET | (1<<ARM_PC), ARM_SP, POP_FD, 1);

// EXIT_TO_INTERPRETER
//   r0 = bci
  handlers[H_EXIT_TO_INTERPRETER] = out_pos(&codebuf);
  ldr_imm(&codebuf, ARM_R1, Ristate, ISTATE_METHOD, 1, 0);
  ldr_imm(&codebuf, ARM_IP, ARM_R1, METHOD_CONSTMETHOD, 1, 0);
  add_reg(&codebuf, Rint_jpc, ARM_IP, ARM_R0);
  mov_imm(&codebuf, ARM_R3, (u32)Thumb2_Exit_To_Interpreter);
  mov_reg(&codebuf, ARM_PC, ARM_R3);

  Thumb2_Clear_Cache(cb->hp, cb->hp + codebuf.idx * 2);
  cb->hp += codebuf.idx * 2;

  thumb2_codebuf = cb;
}

#endif // THUMB2EE
