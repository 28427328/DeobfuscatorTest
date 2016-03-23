uint8_t register_type(uint8_t reg) {
	uint8_t register_type = -1, register_code = 0x60;
	/*
		register_code:

		RAX = 0x50
		EAX = 0x40
		AX = 0x30
		AH = 0x20
		AL = 0x10
	*/
	/*
		register_type:

		RAX = 0x0
		RBX = 0x1
		RCX = 0x2
		RDX = 0x3
		RSP = 0x4
		RBP = 0x5
		RSI = 0x6
		RDI = 0x7
		R8 = 0x8
		R9 = 0x9
		R10 = 0xa
		R11 = 0xb
		R12 = 0xc
		R13 = 0xd
		R14 = 0xe
		R15 = 0xf
	*/
	switch(reg) {
		case X86_REG_AL:
			register_code -= 0x10;
		case X86_REG_AH:
			register_code -= 0x10;
		case X86_REG_AX:
			register_code -= 0x10;
		case X86_REG_EAX:
			register_code -= 0x10;
		case X86_REG_RAX:
			register_code -= 0x10;
			register_type = 0x0;
			break;
		case X86_REG_BL:
			register_code -= 0x10;
		case X86_REG_BH:
			register_code -= 0x10;
		case X86_REG_BX:
			register_code -= 0x10;
		case X86_REG_EBX:
			register_code -= 0x10;
		case X86_REG_RBX:
			register_code -= 0x10;
			register_type = 0x1;
			break;
		case X86_REG_CL:
			register_code -= 0x10;
		case X86_REG_CH:
			register_code -= 0x10;
		case X86_REG_CX:
			register_code -= 0x10;
		case X86_REG_ECX:
			register_code -= 0x10;
		case X86_REG_RCX:
			register_code -= 0x10;
			register_type = 0x2;
			break;
		case X86_REG_DL:
			register_code -= 0x10;
		case X86_REG_DH:
			register_code -= 0x10;
		case X86_REG_DX:
			register_code -= 0x10;
		case X86_REG_EDX:
			register_code -= 0x10;
		case X86_REG_RDX:
			register_code -= 0x10;
			register_type = 0x3;
			break;
		case X86_REG_SPL:
			register_code -= 0x10;
		case X86_REG_SP:
			register_code -= 0x10;
		case X86_REG_ESP:
			register_code -= 0x10;
		case X86_REG_RSP:
			register_code -= 0x10;
			register_type = 0x4;
			break;
		case X86_REG_BPL:
			register_code -= 0x10;
		case X86_REG_BP:
			register_code -= 0x10;
		case X86_REG_EBP:
			register_code -= 0x10;
		case X86_REG_RBP:
			register_code -= 0x10;
			register_type = 0x5;
			break;
		case X86_REG_SIL:
			register_code -= 0x10;
		case X86_REG_SI:
			register_code -= 0x10;
		case X86_REG_ESI:
			register_code -= 0x10;
		case X86_REG_RSI:
			register_code -= 0x10;
			register_type = 0x6;
			break;
		case X86_REG_DIL:
			register_code -= 0x10;
		case X86_REG_DI:
			register_code -= 0x10;
		case X86_REG_EDI:
			register_code -= 0x10;
		case X86_REG_RDI:
			register_code -= 0x10;
			register_type = 0x7;
			break;
		case X86_REG_R8B:
			register_code -= 0x20;
		case X86_REG_R8W:
			register_code -= 0x10;
		case X86_REG_R8D:
			register_code -= 0x10;
		case X86_REG_R8:
			register_code -= 0x10;
			register_type = 0x8;
			break;
		case X86_REG_R9B:
			register_code -= 0x20;
		case X86_REG_R9W:
			register_code -= 0x10;
		case X86_REG_R9D:
			register_code -= 0x10;
		case X86_REG_R9:
			register_code -= 0x10;
			register_type = 0x9;
			break;
		case X86_REG_R10B:
			register_code -= 0x20;
		case X86_REG_R10W:
			register_code -= 0x10;
		case X86_REG_R10D:
			register_code -= 0x10;
		case X86_REG_R10:
			register_code -= 0x10;
			register_type = 0xa;
			break;
		case X86_REG_R11B:
			register_code -= 0x20;
		case X86_REG_R11W:
			register_code -= 0x10;
		case X86_REG_R11D:
			register_code -= 0x10;
		case X86_REG_R11:
			register_code -= 0x10;
			register_type = 0xb;
			break;
		case X86_REG_R12B:
			register_code -= 0x20;
		case X86_REG_R12W:
			register_code -= 0x10;
		case X86_REG_R12D:
			register_code -= 0x10;
		case X86_REG_R12:
			register_code -= 0x10;
			register_type = 0xc;
			break;
		case X86_REG_R13B:
			register_code -= 0x20;
		case X86_REG_R13W:
			register_code -= 0x10;
		case X86_REG_R13D:
			register_code -= 0x10;
		case X86_REG_R13:
			register_code -= 0x10;
			register_type = 0xd;
			break;
		case X86_REG_R14B:
			register_code -= 0x20;
		case X86_REG_R14W:
			register_code -= 0x10;
		case X86_REG_R14D:
			register_code -= 0x10;
		case X86_REG_R14:
			register_code -= 0x10;
			register_type = 0xe;
			break;
		case X86_REG_R15B:
			register_code -= 0x20;
		case X86_REG_R15W:
			register_code -= 0x10;
		case X86_REG_R15D:
			register_code -= 0x10;
		case X86_REG_R15:
			register_code -= 0x10;
			register_type = 0xf;
			break;
		//handle EFLAGS + others
		case X86_REG_EFLAGS:
			register_code = 0xf;
			register_type = 0xf;
		default:
			break;	
	}
	return (register_code | register_type);
}

uint8_t register_from_code(uint8_t code_type) {
	uint8_t type = code_type & 0xF, code = code_type & 0xF0, reg = X86_REG_INVALID;
	//printf("type: 0x%llx\n", type);
	//printf("code: 0x%llx\n", code);
	/*
		register_code:

		RAX = 0x50
		EAX = 0x40
		AX = 0x30
		AH = 0x20
		AL = 0x10
	*/
	/*
		register_type:

		RAX = 0x0
		RBX = 0x1
		RCX = 0x2
		RDX = 0x3
		RSP = 0x4
		RBP = 0x5
		RSI = 0x6
		RDI = 0x7
		R8 = 0x8
		R9 = 0x9
		R10 = 0xa
		R11 = 0xb
		R12 = 0xc
		R13 = 0xd
		R14 = 0xe
		R15 = 0xf
	*/
	switch(type) {
		case 0:
			switch(code) {
				case 0x10:
					reg = X86_REG_AL;
					break;
				case 0x20:
					reg = X86_REG_AH;
					break;
				case 0x30:
					reg = X86_REG_AX;
					break;
				case 0x40:
					reg = X86_REG_EAX;
					break;
				case 0x50:
					reg = X86_REG_RAX;
					break;
			}
			break;
		case 1:
			switch(code) {
				case 0x10:
					reg = X86_REG_BL;
					break;
				case 0x20:
					reg = X86_REG_BH;
					break;
				case 0x30:
					reg = X86_REG_BX;
					break;
				case 0x40:
					reg = X86_REG_EBX;
					break;
				case 0x50:
					reg = X86_REG_RBX;
					break;
			}
			break;
		case 2:
			switch(code) {
				case 0x10:
					reg = X86_REG_CL;
					break;
				case 0x20:
					reg = X86_REG_CH;
					break;
				case 0x30:
					reg = X86_REG_CX;
					break;
				case 0x40:
					reg = X86_REG_ECX;
					break;
				case 0x50:
					reg = X86_REG_RCX;
					break;
			}
			break;
		case 3:
			switch(code) {
				case 0x10:
					reg = X86_REG_DL;
					break;
				case 0x20:
					reg = X86_REG_DH;
					break;
				case 0x30:
					reg = X86_REG_DX;
					break;
				case 0x40:
					reg = X86_REG_EDX;
					break;
				case 0x50:
					reg = X86_REG_RDX;
					break;
			}
			break;
		case 4:
			switch(code) {
				case 0x10:
					reg = X86_REG_SPL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_SP;
					break;
				case 0x40:
					reg = X86_REG_ESP;
					break;
				case 0x50:
					reg = X86_REG_RSP;
					break;
			}
			break;
		case 5:
			switch(code) {
				case 0x10:
					reg = X86_REG_BPL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_BP;
					break;
				case 0x40:
					reg = X86_REG_EBP;
					break;
				case 0x50:
					reg = X86_REG_RBP;
					break;
			}
			break;
		case 6:
			switch(code) {
				case 0x10:
					reg = X86_REG_SIL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_SI;
					break;
				case 0x40:
					reg = X86_REG_ESI;
					break;
				case 0x50:
					reg = X86_REG_RSI;
					break;
			}
			break;
		case 7:
			switch(code) {
				case 0x10:
					reg = X86_REG_DIL;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_DI;
					break;
				case 0x40:
					reg = X86_REG_EDI;
					break;
				case 0x50:
					reg = X86_REG_RDI;
					break;
			}
			break;
		case 8:
			switch(code) {
				case 0x10:
					reg = X86_REG_R8B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R8W;
					break;
				case 0x40:
					reg = X86_REG_R8D;
					break;
				case 0x50:
					reg = X86_REG_R8;
					break;
			}
			break;
		case 9:
			switch(code) {
				case 0x10:
					reg = X86_REG_R9B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R9W;
					break;
				case 0x40:
					reg = X86_REG_R9D;
					break;
				case 0x50:
					reg = X86_REG_R9;
					break;
			}
			break;
		case 0xa:
			switch(code) {
				case 0x10:
					reg = X86_REG_R10B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R10W;
					break;
				case 0x40:
					reg = X86_REG_R10D;
					break;
				case 0x50:
					reg = X86_REG_R10;
					break;
			}
			break;
		case 0xb:
			switch(code) {
				case 0x10:
					reg = X86_REG_R11B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R11W;
					break;
				case 0x40:
					reg = X86_REG_R11D;
					break;
				case 0x50:
					reg = X86_REG_R11;
					break;
			}
			break;
		case 0xc:
			switch(code) {
				case 0x10:
					reg = X86_REG_R12B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R12W;
					break;
				case 0x40:
					reg = X86_REG_R12D;
					break;
				case 0x50:
					reg = X86_REG_R12;
					break;
			}
			break;
		case 0xd:
			switch(code) {
				case 0x10:
					reg = X86_REG_R13B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R13W;
					break;
				case 0x40:
					reg = X86_REG_R13D;
					break;
				case 0x50:
					reg = X86_REG_R13;
					break;
			}
			break;
		case 0xe:
			switch(code) {
				case 0x10:
					reg = X86_REG_R14B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R14W;
					break;
				case 0x40:
					reg = X86_REG_R14D;
					break;
				case 0x50:
					reg = X86_REG_R14;
					break;
			}
			break;
		case 0xf:
			switch(code) {
				case 0x10:
					reg = X86_REG_R15B;
					break;
				case 0x20:
					reg = X86_REG_INVALID;
					break;
				case 0x30:
					reg = X86_REG_R15W;
					break;
				case 0x40:
					reg = X86_REG_R15D;
					break;
				case 0x50:
					reg = X86_REG_R15;
					break;
			}
			break;
	}
	return reg;
}

bool is_same_register_type(uint8_t reg1, uint8_t reg2) {
	return ((register_type(reg1) & 0xF) == (register_type(reg2) & 0xF));
}

bool is_segment_reg(uint8_t reg) {
	switch(reg) {
		case X86_REG_CS:
		case X86_REG_SS:
		case X86_REG_DS:
		case X86_REG_ES:
		case X86_REG_FS:
		case X86_REG_GS:
			return true;
	}
	return false;
}

uint64_t resize_immediate(uint64_t imm, uint8_t reg) {
	uint8_t reg_code = register_type(reg) & 0xF0;
	switch(reg_code) {
		case 0x10:
			imm &= 0xFF;
			break;
		case 0x30:
			imm &= 0xFFFF;
			break;
		case 0x40:
			imm &= 0xFFFFFFFF;
			break;
	}
	return imm;
}

bool is_valid(uint8_t reg) {
	return (reg != X86_REG_INVALID);
}