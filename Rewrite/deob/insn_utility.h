/* Useful information extraction functions */

/*
	Name: is_memory_insn
	Description: this function checks if the instruction uses a
	memory location. Returns FALSE if 'current' is NULL or if
	the 'current' instruction is not using memory.
*/
bool is_memory_insn(Instruction *current) {
	if(!current) return false;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			return true;
		}
	}
	return false;
}

/*
	Name: get_op_count
	Description: this function retrieves the op_coun for a given instruction.
*/
size_t get_op_count(Instruction *current) {
	cs_x86 *x86 = &(current->insn->detail->x86);
	return x86->op_count;
}

/*
	Name: get_op_size
	Description: this function extracts the operand size of an operand, given the operand position.
*/
bool get_op_size(Instruction *current, RegPosition position, uint8_t *size) {
	if(!current) return false;
	size_t op_count = get_op_count(current);
	if(position < op_count) {
		*size = current->insn->detail->x86.operands[position].size;
		return true;
	}
	return false;
}

/*
	Name: get_id
	Description: this function gets the ID from the current instruction
*/
uint32_t get_id(Instruction *current) {
	return current->insn->id;
}

/*
	Name: set_id
	Description: this function sets a new ID for the given instruction.
*/
void set_id(Instruction *current, uint32_t id) {
	current->insn->id = id;
}

/*
	Name: get_reg_at
	Description: this function extracts the register value given an index
	indicating the operand position. If the given position is invalid
	(greater than the number of operands or the operand at that posiztion
	is not a register) the returned value id X86_REG_INVALID.
*/
uint8_t get_reg_at(Instruction *current, RegPosition position) {
	if(!current) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	if(position < op_count) {
		if(x86->operands[position].type == X86_OP_REG) {
			return x86->operands[position].reg;
		}
	}
	return X86_REG_INVALID;
}

/*
	Name: get_base
	Description: this function extracts the base register used by the
	instruction. If not found, it return X86_REG_INVALID.
*/
uint8_t get_base(Instruction *current) {
	if(!current) return X86_REG_INVALID;
	if(!is_memory_insn(current)) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			return op->mem.base;
		}
	}
	return X86_REG_INVALID;
}

/*
	Name: get_index
	Description: this function extracts the index register used by the
	instruction. If not found, it return X86_REG_INVALID.
*/
uint8_t get_index(Instruction *current) {
	if(!is_memory_insn(current)) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			return op->mem.index;
		}
	}
	return X86_REG_INVALID;
}

/*
	Name: get_disp
	Description: this function extracts the displacement used by the memory
	instruction.
*/
bool get_disp(Instruction *current, uint32_t *disp) {
	if(!is_memory_insn(current)) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			*disp = op->mem.disp;
			return true;
		}
	}
	return false;
}

/*
	Name: get_scale
	Description: this function extracts the scale used by the memory instruction.
*/
bool get_scale(Instruction *current, uint32_t *scale) {
	if(!is_memory_insn(current)) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			*scale = op->mem.scale;
			return true;
		}
	}
	return false;
}

/*
	Name: get_imm
	Description: this function extracts the immediate value and if not found,
	the returned value is FALSE, otherwise it is TRUE and the immediate is saved 
	on the 'imm' arguments.
*/
bool get_imm(Instruction *current, uint64_t *imm) {
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_IMM) {
			*imm = op->imm;
			return true;
		}
	}
	return false;
}

/*
	Name: set_disp
	Description: this function is used to update the displacement on a
	memory operation with the one passed as argument.
*/
bool set_disp(Instruction *current, uint32_t disp) {
	if(!current) return false;
	if(!is_memory_insn(current)) return false;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			op->mem.disp = disp;
			return true;
		}
	}
	return false;
}

/*
	Name: set_imm
	Description: this function is used to update the immediate of an
	instruction with the one passed as argument.
*/
bool set_imm(Instruction *current, uint64_t imm) {
	if(!current) return false;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_IMM) {
			op->imm = imm;
			return true;
		}
	}
	return false;
}

/*
	Name: set_reg_at
	Description: this function sets the register at the location indicated
	by 'position'.
*/
bool set_reg_at(Instruction *current, RegPosition position, uint8_t reg) {
	if(!current) return false;
	size_t op_count = get_op_count(current);
	if(position < op_count) {
		if(current->insn->detail->x86.operands[position].type != X86_OP_REG) return false;
		current->insn->detail->x86.operands[position].reg = reg;
		return true;
	}
	return false;
}

/*
	Name: get_mem_size
	Description: this function returns the memory size indicator if found;
	it can be 1/2/4/8. If not found the result is FALSE.
*/
bool get_mem_size(Instruction *current, uint8_t *size) {
	if(!is_memory_insn(current)) return X86_REG_INVALID;
	cs_x86 *x86 = &(current->insn->detail->x86);
	size_t op_count = x86->op_count;
	cs_x86_op *op;
	for(size_t i = 0; i < op_count; i++) {
		op = &(x86->operands[i]);
		if(op->type == X86_OP_MEM) {
			*size = op->size;
			return true;
		}
	}
	return false;
}

/*
	Name: get_mem_indicator
	Description: this function returns a string representation of the
	memory indicator given in input the size value.
*/
char *get_mem_indicator(uint8_t size) {
	//remember to free the allocation when unused
	char *indicator = calloc(8, sizeof(char));
	switch(size) {
		case 1:
			sprintf(indicator, "byte");
			break;
		case 2:
			sprintf(indicator, "word");
			break;
		case 4:
			sprintf(indicator, "dword");
			break;
		case 8:
			sprintf(indicator, "qword");
			break;
		default: break;
	}
	return indicator;
}

/*
	Name: is_dst_reg
	Description: this function checks if the destination is a register
*/
bool is_dst_reg(Instruction *current) {
	if(!current) return false;
	cs_x86 *x86 = current->insn->detail->x86;
	uint8_t type = x86->operands[REG_FIRST].type;
	uint8_t access = x86->operands[REG_FIRST].access;
	return (type == X86_OP_REG && (access == CS_AC_WRITE || access == CS_AC_READ|CS_AC_WRITE));
}

/*
	Name: is_dst_mem
	Description: this function checks if the destionation is a memory location
*/
bool is_dst_mem(Instruction *current) {
	if(!current) return false;
	cs_x86 *x86 = current->insn->detail->x86;
	uint8_t type = x86->operands[REG_FIRST].type;
	uint8_t access = x86->operands[REG_FIRST].access;
	return (type == X86_OP_MEM && (access == CS_AC_WRITE || access == CS_AC_READ|CS_AC_WRITE));
}

/*
	Name: cmp_mnemonic
	Description: compares two mnemonics using strncmp and using
	the length of the second mnemonic. Returns TRUE is equals.
*/
bool cmp_mnemonic(char *mnemonic1, char *mnemonic2) {
	return (strncmp(mnemonic1, mnemonic2, strlen(mnemonic2)) == 0);
}

/*
	Name: cmp_id
	Description: compares two IDs, refer to the Capstone cs_insn.id
	value. On capstone/x86.h you can find all the available IDs.
*/
bool cmp_id(uint32_t id1, uint32_t id2) {
	return (id1 == id2);
}

/*
	Name: print_insn
	Description: prints a string representation of the instruction (mnemonic & op_str)
*/
void print_insn(char *msg, Instruction *current) {
	printf("%s %s %s\n", msg, current->insn->mnemonic, current->insn->op_str);
}

/*
	Name: print_insn_details
	Description: prints a detailed representation of the instruction, with regs/mem/imm info.
*/
void print_insn_details(csh handle, Instruction *current) {
	if(!current) return;
	uint8_t dst_reg = get_reg_at(current, REG_FIRST);
	uint8_t src_reg = get_reg_at(current, REG_SECOND);
	uint8_t base = get_base(current);
	uint8_t index = get_index(current);
	if(is_valid(dst_reg)) printf("REG_FIRST: %s\n", cs_reg_name(handle, dst_reg));
	if(is_valid(src_reg)) printf("REG_SECOND: %s\n", cs_reg_name(handle, src_reg));
	if(is_valid(base)) printf("base: %s\n", cs_reg_name(handle, base));
	if(is_valid(index)) printf("index: %s\n", cs_reg_name(handle, index));
	uint32_t scale;
	if(get_scale(current, &scale)) printf("scale: 0x%lx\n", scale);
	uint32_t disp;
	if(get_disp(current, &disp)) printf("disp: 0x%lx\n", disp);
	uint64_t imm;
	if(get_imm(current, &imm)) printf("imm: 0x%lx\n", imm);
}

/* Assemblying & Updating an instruction */

bool update_disasm(Instruction *insn, uint64_t address, uint8_t mode) {
	csh handle;
	size_t count;
	if(cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
		printf("[-] Error: cs_open, cannot start disassembler.\n");
		return false;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, insn->insn->bytes, insn->insn->size, address, 0, &insn->insn);
	if(count >= 1) {
	} else {
		printf("[-] Error: cs_disasm, error while disassembling.\n");
		return false;
	}
	cs_close(&handle);
	return true;
}

bool reassemble(Instruction *insn, uint8_t mode) {
	//checking if "assemble" function is imported
	if(!assemble) {
		printf("[-] assemble(XEDParse *xedparse) function not found!\n");
		return false;
	}
	XEDPARSE_STATUS result;
	XEDPARSE parse;
	switch(mode) {
		case CS_MODE_32:
			parse.x64 = false;
			break;
		case CS_MODE_64:
			parse.x64 = true;
			break;
	}
	parse.cip = 0;
	char instr[256] = "";
	strcat(instr, insn->insn->mnemonic);
	strcat(instr, " ");
	strcat(instr, insn->insn->op_str);
	instr[strlen(instr)] = 0;
	strcpy(parse.instr, instr);
	result = assemble(&parse);
	//result = XEDParseAssemble(&parse);
	if(result == XEDPARSE_ERROR) {
		if(VERBOSE_ERROR)
			printf("[!] Error: \"%s\" while assembling \"%s\"\n", parse.error, parse.instr);
		return false;
	}
	insn->insn->size = parse.dest_size;
	memcpy(insn->insn->bytes, parse.dest, parse.dest_size);
	return result;
}

Instruction *assemble_insn(char *mnemonic, char *op_str, uint64_t address, uint8_t mode) {
	Instruction *new_insn = calloc(1, sizeof(Instruction));
	new_insn->insn = calloc(1, sizeof(cs_insn));
	sprintf(new_insn->insn->mnemonic, mnemonic);
	sprintf(new_insn->insn->op_str, op_str);
	if(!(reassemble(new_insn, mode) && update_disasm(new_insn, address, mode))) {
		free(new_insn->insn);
		free(new_insn);
		return NULL;
	} else {
		return new_insn;
	}
}

Instruction *assemble_fake_insn(char *mnemonic, char *original_op_str, char *fake_op_str, uint64_t address, uint8_t mode) {
	Instruction *new_insn = assemble_insn(mnemonic, original_op_str, address, mode);
	if(new_insn) {
		//copy fake op_str
		sprintf(new_insn->insn->op_str, fake_op_str);
		//convert the instruction bytes to NOPs
		memset(new_insn->insn->bytes, 0x90, new_insn->insn->size);
		//mark the instruction as invalid
		new_insn->invalid = true;
		return new_insn;
	} else {
		return NULL;
	}
}

/* Instruction search & access flags */

/*
	Name: find_insn
	Description: this function is used to find an Instruction matching the "pattern details" passed using InsnMatch.
*/
ListEntry *find_insn(ListEntry *start, ListEntry *end, InsnMatch *insn) {
	//check if the start is invalid
	if(!start) return NULL;
	//check if start is before end
	ListEntry *temp = start;
	if(ListIsBefore(start, end) != start) return NULL;
	//start searching the pattern instruction
	ListEntry *result, *current = start;
	//Capstone variables
	cs_x86 *x86;
	cs_x86_op *op;
	size_t op_count;
	//Temporary variables for operands
	Instruction *instruction;
	while(current && current != end) {
		//get Instruction from ListEntry
		instruction = (Instruction *)current->content;
		//check instruction and instruction->insn
		if(!instruction || !instruction->insn) {
			printf("[!] Error with find_insn!\n");
			ExitProcess(EXIT_FAILURE);
		}
		//first check the mnemonic
		if(cmp_id(instruction->insn->id, insn->id)) {
			//printf("checking current: %s %s\n", instruction->insn->mnemonic, instruction->insn->op_str);
			InsnMatch insn_l = {};
			//extract operands from the instructions
			x86 = &(instruction->insn->detail->x86);
			op_count = x86->op_count;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				switch(op->type) {
					case X86_OP_REG:
						if(i == 0) {
							insn_l.dst_reg = op->reg;
						} else {
							insn_l.src_reg = op->reg;
						}
						break;
					case X86_OP_MEM:
						insn_l.mem.base = op->mem.base;
						insn_l.mem.index = op->mem.index;
						insn_l.mem.scale = (uint32_t)op->mem.scale;
						insn_l.mem.disp = (uint32_t)op->mem.disp;
						break;
					case X86_OP_IMM:
						insn_l.src_imm = op->imm;
						break;
				}
			}
			//determine current instruction InsnType
			uint8_t dst_type = x86->operands[0].type, src_type = x86->operands[1].type;
			if(dst_type == X86_OP_REG) {
				switch(src_type) {
					case X86_OP_REG:
						insn_l.type = X86_DST_REG_SRC_REG;
						break;
					case X86_OP_MEM:
						insn_l.type = X86_DST_REG_SRC_MEM;
						break;
					case X86_OP_IMM:
						insn_l.type = X86_DST_REG_SRC_IMM;
						break;
					default:
						insn_l.type = X86_DST_REG;
						break;
				}
			} else if(dst_type == X86_OP_MEM) {
				switch(src_type) {
					case X86_OP_REG:
						insn_l.type = X86_DST_MEM_SRC_REG;
						break;
					case X86_OP_IMM:
						insn_l.type = X86_DST_MEM_SRC_IMM;
						break;
					default:
						insn_l.type = X86_DST_MEM;
						break;
				}
			} else if(dst_type == X86_OP_IMM) {
				insn_l.type = X86_DST_IMM;
			} else {
				insn_l.type = X86_NO_OP;
			}
			//check for general or specific match
			if(!insn->specific_match) {
				//printf("insn_l.type (%d) == (%d) insn->type\n", insn_l.type, insn->type);
				if(insn_l.type == insn->type) return current;
			} else {
				//check if the operands are the right ones
				switch(insn->type) {
					case X86_DST_REG_SRC_REG:
						if((insn->wildcard_dst_reg || insn_l.dst_reg == insn->dst_reg) && (insn->wildcard_src_reg || insn_l.src_reg == insn->src_reg)) return current;
						break;
					case X86_DST_REG_SRC_MEM:
						if((insn->wildcard_dst_reg || insn_l.dst_reg == insn->dst_reg) && (insn->wildcard_mem || (insn_l.mem.base == insn->mem.base && insn_l.mem.index == insn->mem.index && insn_l.mem.scale == insn->mem.scale && insn_l.mem.disp == insn->mem.disp))) return current;
						break;
					case X86_DST_REG_SRC_IMM:
						if((insn->wildcard_dst_reg || insn_l.dst_reg == insn->dst_reg) && (insn->wildcard_imm || insn_l.src_imm == insn->src_imm)) return current;
						break;
					case X86_DST_MEM_SRC_REG:
						if((insn->wildcard_mem || (insn_l.mem.base == insn->mem.base && insn_l.mem.index == insn->mem.index && insn_l.mem.scale == insn->mem.scale && insn_l.mem.disp == insn->mem.disp)) && (insn->wildcard_src_reg || insn_l.src_reg == insn->src_reg)) return current;
						break;
					case X86_DST_MEM_SRC_IMM:
						if((insn->wildcard_mem || (insn_l.mem.base == insn->mem.base && insn_l.mem.index == insn->mem.index && insn_l.mem.scale == insn->mem.scale && insn_l.mem.disp == insn->mem.disp)) && (insn->wildcard_imm || insn_l.src_imm == insn->src_imm)) return current;
						break;
					case X86_DST_REG:
						if(insn->wildcard_dst_reg || insn_l.dst_reg == insn->dst_reg) return current;
						break;
					case X86_DST_MEM:
						if(insn->wildcard_mem || (insn_l.mem.base == insn->mem.base && insn_l.mem.index == insn->mem.index && insn_l.mem.scale == insn->mem.scale && insn_l.mem.disp == insn->mem.disp)) return current;
						break;
					case X86_NO_OP:
						return current;
						break;
				}
			}
		}
		//pass to the next instruction
		current = current->next;
	}
	return NULL;
}

/*	
	Name: find_insn_op_access
	Description: this function is used to find out what instruction accesses REG or MEM in a certain way (READ - WRITE - READ|WRITE).
	The specific flag is used to check if the access is general or a specific type (READ - WRITE - READ|WRITE).
*/
ListEntry *find_insn_op_access(ListEntry *start, ListEntry *end, InsnAccess *acc) {
	//check if start is valid
	if(!start) return NULL;
	//check if start is before end
	if(ListIsBefore(start, end) != start) return NULL;
	ListEntry *current = start;
	//Capstone variables
	cs_x86 *x86;
	cs_x86_op *op;
	size_t op_count;
	//Useful variables
	Instruction *insn;
	while(current && current != end) {
		//extract Instruction from ListEntry
		insn = (Instruction *)current->content;
		//check if InsnAccess is found
		x86 = &(insn->insn->detail->x86);
		op_count = x86->op_count;
		for(size_t i = 0; i < op_count; i++) {
			op = &(x86->operands[i]);
			switch(op->type) {
				case X86_OP_REG:
					if(op->access == acc->access_type && op->type == acc->op_type) {
						if(acc->same_reg) {
							if(op->reg == acc->reg) return current;
						} else {
							if(is_same_register_type(op->reg, acc->reg)) return current;
						}
					}
					break;
				case X86_OP_MEM:
					if(acc->op_type == X86_OP_MEM) {
						if(op->mem.base == acc->mem.base && op->mem.index == acc->mem.index && (uint32_t)op->mem.scale == acc->mem.scale && (uint32_t)op->mem.disp == acc->mem.disp) {
							if(op->access == acc->access_type) return current;
						}
					} else if(acc->op_type == X86_OP_REG) {
						if(acc->same_reg) {
							if(acc->access_type == CS_AC_READ && (op->mem.base == acc->reg || op->mem.index == acc->reg)) return current;
						} else {
							if(acc->access_type == CS_AC_READ && (is_same_register_type(op->mem.base, acc->reg) || is_same_register_type(op->mem.index, acc->reg))) return current;
						}
					}
					break;
			}
		}
		current = current->next;
	}
	return NULL;
}

/*
	Name: find_insn_op_general_access
	Description: This function is used to find the first general access to REG or MEM; with general access is indicated
	the first READ or WRITE or READ|WRITE operation accessing REG or MEM.
*/

ListEntry *find_insn_op_general_access(ListEntry *start, ListEntry *end, InsnAccess *acc) {
	if(start == NULL) return NULL;
	//if(VERBOSE && start) print_insn("[I] start: ", start->content);
	//if(VERBOSE && end) print_insn("[I] end: ", end->content);
	acc->access_type = CS_AC_WRITE;
	ListEntry *write_only = find_insn_op_access(start, end, acc);
	acc->access_type = CS_AC_READ;
	ListEntry *read_only = find_insn_op_access(start, end, acc);
	acc->access_type = CS_AC_READ|CS_AC_WRITE;
	ListEntry *read_or_write = find_insn_op_access(start, end, acc);
	//if(VERBOSE && write_only) print_insn("[I] write_only: ", write_only->content);
	//if(VERBOSE && read_only) print_insn("[I] read_only: ", read_only->content);
	//if(VERBOSE && read_or_write) print_insn("[I] read_or_write: ", read_or_write->content);
	ListEntry *first = ListIsBefore(write_only, read_only);
	first = ListIsBefore(first, read_or_write);
	//if(VERBOSE && first) print_insn("[I] find_insn_op_general_access: ", first->content);
	return first;
}

/* Instruction updating functions */

bool is_strange_reg(uint8_t reg) {
	//this is an array of registers that cannot be directly used in an instruction
	uint8_t strange_reg[1] = { X86_REG_EFLAGS };
	for(size_t i = 0; i < 1; i++) {
		if(reg == strange_reg[i]) {
			return true;
		}
	}
	return false;
}

//---------------------------------------------------------------------------------------------------------------------------------

/*
	Name: prettify_mem
	Description: this function is useless, it will fix the op_str of an invalid memory instruction just to make
	it easier to read.
*/
/*char *prettify_mem(csh handle, uint8_t base, uint8_t index, uint32_t scale, uint32_t disp, uint8_t src_reg, uint8_t dst_reg, uint8_t size) {
	//remember to free it when unused
	char *pretty_op_str = calloc(0xFF, sizeof(char));
	//fix memory part
	char *base_s = (is_valid(base)) ? cs_reg_name(handle, base) : "";
	char *index_s = (is_valid(index)) ? cs_reg_name(handle, index) : "";
	char *scale_s = calloc(10, sizeof(char));
	char *disp_s = calloc(10, sizeof(char));
	char *mem_size = get_mem_indicator(size);
	if(scale != 1) sprintf(scale, " * 0x%lx", scale);
	if(disp != 0) sprintf(disp, " + 0x%lx", disp);
	//generate full op_str
	if(is_valid(dst_reg)) {
		sprintf(pretty_op_str, "%s, %s ptr [%s%s%s%s]", cs_reg_name(handle, dst_reg), mem_size, base_s, index_s, scale_s, disp_s);
	} else if(is_valid(src_reg)) {
		sprintf(pretty_op_str, "%s ptr [%s%s%s%s], %s", mem_size, base_s, index_s, scale_s, disp_s, cs_reg_name(handle, src_reg));
	}
	return pretty_op_str;
}*/

/*
	Name: update_insn_str
	Description: this function tries to generate a valid Instruction representation of an updated instruction.
	It extracts all the information, understand what the instruction looks like and assemble the new one.
	The main limitation is that it can handle only 0/1/2 operands instructions, maybe in the future, if needed,
	it will be updated.
*/
Instruction *update_insn_str(csh handle, Instruction *old_insn, uint8_t mode) {
	if(!old_insn) return NULL;
	//extract operands count
	uint8_t op_count = get_op_count(old_insn);
	//check op_count < 3
	if(op_count > 2) {
		printf("[!] Error, op_count > 2 not supported!\n");
		ExitProcess(EXIT_FAILURE);
		return NULL;
	}
	//extract registers information
	uint8_t dst_reg = get_reg_at(old_insn, REG_FIRST);
	uint8_t src_reg = get_reg_at(old_insn, REG_SECOND);
	//check if source or destination registers are strange
	bool dst_reg_strange = is_strange_reg(dst_reg);
	bool src_reg_strange = is_strange_reg(src_reg);
	//extract memory information
	uint8_t size;
	bool size_found = get_mem_size(old_insn, &size);
	uint8_t base = get_base(old_insn);
	uint8_t index = get_index(old_insn);
	uint32_t scale, disp;
	get_scale(old_insn, &scale);
	get_disp(old_insn, &disp);
	uint64_t imm;
	bool imm_found = get_imm(old_insn, &imm);
	//generate the mnemonic using id
	char *mnemonic = (char *)cs_insn_name(handle, old_insn->insn->id);
	//generate the op_str using the extracted information
	char *op_str = calloc(0xFF, sizeof(char));
	char *fake_op_str = (dst_reg_strange || src_reg_strange) ? calloc(0xFF, sizeof(char)) : NULL;
	if(op_count == 0) {
		//the instruction is made up only by the mnemonic, so it is X86_NO_OP
	} if(is_memory_insn(old_insn)) {
		//generate the memory size indicator string
		char *indicator = (size_found) ? get_mem_indicator(size) : "";
		if(is_valid(dst_reg)) {
			//check if it is X86_DST_REG_SRC_MEM
			if(dst_reg_strange) {
				uint8_t fake_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(op_str, "%s, %s [%s + %s * 0x%lx + 0x%lx]", cs_reg_name(handle, fake_reg), indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
				sprintf(fake_op_str, "%s, %s [%s + %s * 0x%lx + 0x%lx]", cs_reg_name(handle, dst_reg), indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
			} else {
				sprintf(op_str, "%s, %s [%s + %s * 0x%lx + 0x%lx]", cs_reg_name(handle, dst_reg), indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
			}
		} else if(is_valid(src_reg)) {
			//check if it is X86_DST_MEM_SRC_REG
			if(src_reg_strange) {
				uint8_t fake_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(op_str, "%s [%s + %s * 0x%lx + 0x%lx], %s", indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, fake_reg));
				sprintf(fake_op_str, "%s [%s + %s * 0x%lx + 0x%lx], %s", indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, src_reg));
			} else {
				sprintf(op_str, "%s [%s + %s * 0x%lx + 0x%lx], %s", indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, src_reg));
			}
		} else if(imm_found) {
			//check if it is X86_DST_MEM_SRC_IMM
			sprintf(op_str, "%s [%s + %s * 0x%lx + 0x%lx], 0x%llx", indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, imm);
		} else if(op_count == 1) {
			//check if it is X86_DST_MEM
			sprintf(op_str, "%s [%s + %s * 0x%lx + 0x%lx]", indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
		}
	} else {
		if(is_valid(src_reg) && is_valid(dst_reg)) {
			//check if it is X86_DST_REG_SRC_REG
			if(src_reg_strange) {
				uint8_t fake_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(op_str, "%s, %s", cs_reg_name(handle, fake_reg), cs_reg_name(handle, fake_reg));
				sprintf(fake_op_str, "%s, %s", cs_reg_name(handle, dst_reg), cs_reg_name(handle, src_reg));
			} else if(dst_reg_strange) {
				uint8_t fake_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(op_str, "%s, %s", cs_reg_name(handle, fake_reg), cs_reg_name(handle, src_reg));
				sprintf(fake_op_str, "%s, %s", cs_reg_name(handle, dst_reg), cs_reg_name(handle, src_reg));
			} else {
				sprintf(op_str, "%s, %s", cs_reg_name(handle, dst_reg), cs_reg_name(handle, src_reg));
			}
		} else if(is_valid(dst_reg) && imm_found) {
			//check if it is X86_DST_REG_SRC_IMM
			if(dst_reg_strange) {
				uint8_t fake_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX; 
				sprintf(op_str, "%s, 0x%llx", cs_reg_name(handle, fake_reg), imm);
				sprintf(fake_op_str, "%s, 0x%llx", cs_reg_name(handle, dst_reg), imm);
			} else {
				sprintf(op_str, "%s, 0x%llx", cs_reg_name(handle, dst_reg), imm);
			}
		} else if(op_count == 1) {
			//check if it is X86_DST_REG
			sprintf(op_str, "%s", cs_reg_name(handle, dst_reg));
		}
	}
	//assemble new instruction
	Instruction *new_insn = assemble_insn(mnemonic, op_str, old_insn->insn->address, mode);
	//check if the instruction was invalid
	if(old_insn->invalid) {
		//fix op_str
		sprintf(new_insn->insn->op_str, fake_op_str);
		//fix registers
		if(dst_reg_strange) {
			set_reg_at(new_insn, REG_FIRST, dst_reg);
		} else if(src_reg_strange) {
			set_reg_at(new_insn, REG_SECOND, src_reg);
		} else {
			printf("[!] Error while assembling the INVALID instruction!\n");
			ExitProcess(EXIT_FAILURE);
			return NULL;
		}
	}
	/*if(VERBOSE && new_insn) {
		print_insn("[I] Updated instruction: ", new_insn);
		//print_insn_details(handle, new_insn);
	}*/
	if(!new_insn) {
		printf("[!] Error while assembling the instruction!\n");
		ExitProcess(EXIT_FAILURE);
	}
	//free space
	//free(mnemonic);
	//free(op_str);
	return new_insn;
}