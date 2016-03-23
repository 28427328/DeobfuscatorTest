#include <stdio.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <windows.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <unicorn/unicorn.h>
#include <XEDParse/XEDParse.h>
#include <deob/flags.h>

typedef enum InsnType {
	X86_DST_REG_SRC_REG = 0,
	X86_DST_REG_SRC_MEM,
	X86_DST_REG_SRC_IMM,
	X86_DST_MEM_SRC_REG,
	X86_DST_MEM_SRC_IMM,
	X86_DST_REG,
	X86_DST_MEM,
	X86_DST_IMM,
	X86_NO_OP
} InsnType;

typedef enum RegPosition {
	REG_FIRST = 0,
	REG_SECOND,
	REG_THIRD,
	REG_FOURTH
} RegPosition;

typedef struct Instruction {
	cs_insn *insn;					//pointer to the Capstone structure cs_insn
	bool invalid;					//it indicates if the instruction is a fake one (e.g. mov eax, eflags)
} Instruction;

typedef struct MemoryLocation {
	uint8_t base;
	uint8_t index;
	uint32_t scale;
	uint32_t disp;
} MemoryLocation;

typedef struct MemoryValue {
	uint64_t address;
	uint64_t value;
	uint32_t size;
} MemoryValue;

typedef struct Registers {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t rip;
} Registers;

typedef struct InsnMatch {
	InsnType type;				//indicates the type of instruction to match
	uint32_t id;				//it is the instruction opcode, refer to x86_insn from Capstone
	uint8_t dst_reg;			//destination register
	uint8_t src_reg;			//source register
	//uint8_t third_reg;		//third register -> unused for now
	//uint8_t fourth_reg;		//fourth register -> unused for now
	uint64_t src_imm;			//source immediate
	MemoryLocation mem;			//memory location structure: base, index, scale, displacement
	bool specific_match;		//used to know if we need a specific match or a general (only the 'type' is checked)
	bool wildcard_dst_reg;		//wildcard flag for dst_reg, when set dst_reg is ignored
	bool wildcard_src_reg;		//wildcard flag for src_reg, when set src_reg is ignored
	bool wildcard_mem;			//wildcard flag for mem, when set mem is ignored
	bool wildcard_imm;			//wildcard flag for imm, when set imm is ignored
} InsnMatch;

typedef struct InsnAccess {
	uint8_t access_type;		//determine the access type, using the Capstone ones: CS_AC_READ, CS_AC_WRITE & (CS_AC_READ|CS_AC_WRITE)
	uint8_t op_type;			//determine the type of the operand to check, using the Capstone ones: X86_OP_REG, X86_OP_MEM & X86_OP_IMM
	uint8_t reg;				//the register to trace
	MemoryLocation mem;			//the memory location to trace
	bool same_reg;				//used to know if we want an equality check of the register, or a is_same_register_type is ok 
} InsnAccess;
