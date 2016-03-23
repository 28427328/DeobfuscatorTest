#include <deob/op_utility.h>
#include <deob/insn_utility.h>

/*
	Name: expand_stack_ins
	Description: this function is used to expand
	a list of instruction to facilitate the analysis
	& possible optimization of the stack or memory.
	Current expansion list:

		-------------PUSH-------------
		0 = PUSH IMM
		1 = PUSH REG
		2 = PUSH SEG
		3 = PUSH [BASE+INDEX*SCALE+DISP]
		4 = PUSHF
		-- 5 = PUSHFD
		-- 6 = PUSHFQ
		-- 7 = PUSHAW (Intel Manual: PUSHA)
		8 = PUSHAL (Intel Manual: PUSHAD)
		-------------POP--------------
		9 = POP REG
		10 = POP SEG
		11 = POP [BASE+INDEX*SCALE+DISP]
		12 = POPF
		-- 13 = POPFD
		-- 14 = POPFQ
		-- 15 = POPAW (Intel Manual: POPA)
		16 = POPAL (Intel Manual: POPAD)
		-------------MOV--------------
		17 = MOV REG, ESP/RSP
		18 = MOV[BASE+INDEX*SCALE+DISP], ESP/RSP
		-------------XCHG-------------
		19 = XCHG [BASE+INDEX*SCALE+DISP], REG
		20 = XCHG REG1, REG2
		-------------LEA--------------
		21 = LEA REG, [BASE+INDEX*SCALE+DISP]
		------------------------------
		0xFF = Do not expand
*/

bool expand_stack_ins(csh handle, List *list, uint8_t mode) {
	bool optimized = false;
	//check if list contains at least an instruction
	if(!list->first) return false;
	//start the expansion from the first instruction
	ListEntry *current = list->first, *next;
	//setup Capstone variables
	cs_insn *insn;
	cs_x86 *x86;
	cs_x86_op *op;
	size_t op_count;
	//ID is the instruction expansion identifier
	uint8_t ID;
	Instruction *current_insn;
	while(current) {
		//printf("current: %s %s\n", current->insn->mnemonic, current->insn->op_str);
		next = current->next;
		//reset instruction ID = 0xFF = Do not expand
		ID = 0xFF;
		//identify instruction (using mnemonic & operands)
		current_insn = (Instruction *)current->content;
		insn = current_insn->insn;
		if(strncmp(insn->mnemonic, "push", 4) == 0) {
			if(strncmp(insn->mnemonic, "pushf", 5) == 0) {
				ID = 4;
			} else if(strncmp(insn->mnemonic, "pushal", 6) == 0) {
				ID = 8;
			}
			//If the instruction is none of the above check for 1/2/3
			x86 = &(insn->detail->x86);
			op_count = x86->op_count;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				switch(op->type) {
					case X86_OP_REG:
						ID = (is_segment_reg(op->reg)) ? 2 : 1;
						break;
					case X86_OP_MEM:
						ID = 3;
						break;
					case X86_OP_IMM:
						ID = 0;
						break;
				}
			}
		} else if(strncmp(insn->mnemonic, "pop", 3) == 0) {
			if(strncmp(insn->mnemonic, "popf", 4) == 0) {
				ID = 12;
			} else if(strncmp(insn->mnemonic, "popal", 5) == 0) {
				ID = 16;
			}
			//If the instruction is none of the above check for 9/10/11
			x86 = &(insn->detail->x86);
			op_count = x86->op_count;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				switch(op->type) {
					case X86_OP_REG:
						ID = (is_segment_reg(op->reg)) ? 10 : 9;
						break;
					case X86_OP_MEM:
						ID = 11;
						break;
				}
			}
		} else if(strncmp(insn->mnemonic, "mov", 3) == 0) {
			//check if it is "MOV REG, ESP"
			x86 = &(insn->detail->x86);
			op_count = x86->op_count;
			bool dest_reg_found = false, src_reg_found = false, mem_write_found = false, src_esp_found = false;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				if(op->access == CS_AC_WRITE && op->type == X86_OP_REG)	dest_reg_found = true;
				if(op->access == CS_AC_READ && op->type == X86_OP_REG && op->reg != X86_REG_INVALID && is_same_register_type(op->reg, X86_REG_RSP)) src_reg_found = true;
				if(op->type == X86_OP_MEM && ((op->mem.base == X86_REG_ESP) || (op->mem.base == X86_REG_RSP))) mem_write_found = true;
				if(op->access == CS_AC_READ && op->type == X86_OP_REG && is_same_register_type(op->reg, X86_REG_RSP)) src_esp_found = true;
			}
			if(dest_reg_found && src_reg_found) ID = 17;
			if(src_esp_found && mem_write_found) ID = 18;
		} else if(strncmp(insn->mnemonic, "xchg", 4) == 0) {
			//check if it is "XCHG [MEM], REG"
			x86 = &(insn->detail->x86);
			op_count = x86->op_count;
			for(size_t i = 0; i < op_count; i++) {
				op = &(x86->operands[i]);
				if(op->type == X86_OP_MEM) ID = 19;
			}
			//if ID == 0xFF this is not "XCHG [MEM], REG", it is "XCHG REG1, REG2"
			if(ID == 0xFF) ID = 20;
		} else if(strncmp(insn->mnemonic, "lea", 3) == 0) {
			//this is a general lea instruction
			ID = 21;
		}
		//apply expansion based on the ID
		switch(ID) {
			//0 = PUSH IMM
			case 0: {
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *sub = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(sub->mnemonic, "sub");
				//uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				uint8_t op_size;
				get_op_size(current_insn, REG_FIRST, &op_size);
				char *mem_size = calloc(10, sizeof(char));
				switch(op_size) {
					case 1:
						sprintf(mem_size, "byte");
						break;
					case 2:
						sprintf(mem_size, "word");
						break;
					case 4:
						sprintf(mem_size, "dword");
						break;
					case 8:
						sprintf(mem_size, "qword");
						break;
				}
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP; 
				sprintf(mov->op_str, "%s ptr [%s - %d], %s", mem_size, cs_reg_name(handle, esp_reg), op_size, insn->op_str);
				sprintf(sub->op_str, "%s, %d", cs_reg_name(handle, esp_reg), op_size);
				//assembling new Instructions
				Instruction *mov_ins = assemble_insn(mov->mnemonic, mov->op_str, TEXT_ADDRESS, mode);
				Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
				if(!mov_ins || !sub_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//printf("\noriginal: %s %s\n", insn->mnemonic, insn->op_str);
					//printf("%s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
					//printf("%s %s\n", sub_ins->insn->mnemonic, sub_ins->insn->op_str);
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *sub_entry = ListEntryCreate(sub_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov_entry);
					ListInsertAfter(list, mov_entry, sub_entry);
					ListRemove(list, current);
					free(mov);
					free(sub);
					optimized = true;
					break;
				}
			}
			//1 = PUSH REG
			case 1: {
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *sub = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(sub->mnemonic, "sub");
				//find out if the pushed register is 16/32/64 bit
				uint8_t op_size = 0;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG) {
						switch(register_type(op->reg) & 0xF0) {
							case 0x30:
								op_size = 16;
								break;
							case 0x40:
								op_size = 32;
								break;
							case 0x50:
								op_size = 64;
								break;
						}
					}
				}
				if(op_size == 0) {
					printf("[!] Error retrieving pushed register size in bits\n");
					return false;
				}
				//generating correct instructions
				switch(mode) {
					case CS_MODE_32:
						switch(op_size) {
							case 16:
								sprintf(mov->op_str, "[esp-2], %s", insn->op_str);
								sprintf(sub->op_str, "esp, 2");
								break;
							case 32:
								sprintf(mov->op_str, "[esp-4], %s", insn->op_str);
								sprintf(sub->op_str, "esp, 4");
								break;
						}
						break;
					case CS_MODE_64:
						switch(op_size) {
							case 16:
								sprintf(mov->op_str, "[rsp-2], %s", insn->op_str);
								sprintf(sub->op_str, "rsp, 2");
								break;
							case 32:
								sprintf(mov->op_str, "[rsp-4], %s", insn->op_str);
								sprintf(sub->op_str, "rsp, 4");
								break;
							case 64:
								sprintf(mov->op_str, "[rsp-8], %s", insn->op_str);
								sprintf(sub->op_str, "rsp, 8");
								break;
						}
						break;
				}
				//assembling new Instructions
				Instruction *mov_ins = assemble_insn(mov->mnemonic, mov->op_str, TEXT_ADDRESS, mode);
				Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
				if(!mov_ins || !sub_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//printf("\noriginal: %s %s\n", insn->mnemonic, insn->op_str);
					//printf("%s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
					//printf("%s %s\n", sub_ins->insn->mnemonic, sub_ins->insn->op_str);
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *sub_entry = ListEntryCreate(sub_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov_entry);
					ListInsertAfter(list, mov_entry, sub_entry);
					ListRemove(list, current);
					free(mov);
					free(sub);
					optimized = true;
				}
				break;
			}
			//2 = PUSH SEG
			case 2: {
				//	This instruction cannot be converted into a pair "MOV/SUB", I will handle it in this way:
				//		1) I will create a fake instruction "MOV [MEM], SEG" + "SUB ESP/RSP, 4/8"
				//		2) I will mark the instruction as INVALID, so other optimization methods can ignore it if needed
				//retrieve real SEGMENT register
				uint8_t seg_reg = X86_REG_INVALID;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG) {
						seg_reg = op->reg;
					}
				}
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *sub = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(sub->mnemonic, "sub");
				char *fake_op_str = calloc(40, sizeof(char));
				uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				uint8_t src_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(mov->op_str, "[%s-%d], %s", cs_reg_name(handle, esp_reg), displacement, cs_reg_name(handle, src_reg));
				sprintf(mov->op_str, "[%s-%d], %s", cs_reg_name(handle, esp_reg), displacement, cs_reg_name(handle, seg_reg));
				sprintf(sub->op_str, "%s, %d", cs_reg_name(handle, esp_reg), displacement);
				//generating new Instructions
				Instruction *mov_ins = assemble_fake_insn(mov->mnemonic, mov->op_str, fake_op_str, TEXT_ADDRESS, mode);
				Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
				if(!mov_ins || !sub_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//fixing fake operands
					mov_ins->insn->detail->x86.operands[1].reg = seg_reg;
					//create ListEntry
					//printf("\noriginal: %s %s\n", insn->mnemonic, insn->op_str);
					//printf("%s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
					//printf("%s %s\n", sub_ins->insn->mnemonic, sub_ins->insn->op_str);
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *sub_entry = ListEntryCreate(sub_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov_entry);
					ListInsertAfter(list, mov_entry, sub_entry);
					ListRemove(list, current);
					free(fake_op_str);
					free(mov);
					free(sub);
					optimized = true;
				}
				break;
			}
			//3 = PUSH [BASE+INDEX*SCALE+DISP]
			case 3: {
				//extract base, index, scale & displacement from the current instruction
				uint32_t disp = 0, scale = 1;
				uint8_t base = X86_REG_INVALID, index = X86_REG_INVALID, mem_size = 0;
				x86 = &(current_insn->insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_MEM) {
						base =op->mem.base;
						index = op->mem.index;
						scale = (uint32_t)op->mem.scale;
						disp = (uint32_t)op->mem.disp;
						mem_size = op->size;
					}
				}
				//generating mnemonic & op_str
				cs_insn *mov1 = calloc(1, sizeof(cs_insn));
				cs_insn *mov2 = calloc(1, sizeof(cs_insn));
				cs_insn *mov3 = calloc(1, sizeof(cs_insn));
				cs_insn *mov4 = calloc(1, sizeof(cs_insn));
				cs_insn *sub = calloc(1, sizeof(cs_insn));
				sprintf(mov1->mnemonic, "mov");
				sprintf(mov2->mnemonic, "mov");
				sprintf(mov3->mnemonic, "mov");
				sprintf(mov4->mnemonic, "mov");
				sprintf(sub->mnemonic, "sub");
				//generate memory size indicator
				char *mem_size_indicator = calloc(20, sizeof(char));
				switch(mem_size) {
					case 1:
						sprintf(mem_size_indicator, "byte");
						break;
					case 2:
						sprintf(mem_size_indicator, "word");
						break;
					case 4:
						sprintf(mem_size_indicator, "dword");
						break;
					case 8:
						sprintf(mem_size_indicator, "qword");
						break;
				}
				//generate instructions op_str
				uint8_t src_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				sprintf(mov1->op_str, "[%s - 0x%lx], %s", cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT, cs_reg_name(handle, src_reg));
				sprintf(mov2->op_str, "%s, [%s + %s * 0x%lx + 0x%lx]", cs_reg_name(handle, src_reg), cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
				sprintf(mov3->op_str, "%s [%s - %d], %s", mem_size_indicator, cs_reg_name(handle, esp_reg), displacement, cs_reg_name(handle, src_reg));
				sprintf(sub->op_str, "%s, %d", cs_reg_name(handle, esp_reg), mem_size);
				sprintf(mov4->op_str, "%s, [%s - 0x%lx]", cs_reg_name(handle, src_reg), cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT);
				//printf("%s, %s\n", mov1->mnemonic, mov1->op_str);
				//printf("%s, %s\n", mov2->mnemonic, mov2->op_str);
				//printf("%s, %s\n", mov3->mnemonic, mov3->op_str);
				//printf("%s, %s\n", mov4->mnemonic, mov4->op_str);
				//printf("%s, %s\n", sub->mnemonic, sub->op_str);
				//generating new Instructions
				Instruction *mov1_ins = assemble_insn(mov1->mnemonic, mov1->op_str, TEXT_ADDRESS, mode);
				Instruction *mov2_ins = assemble_insn(mov2->mnemonic, mov2->op_str, TEXT_ADDRESS, mode);
				Instruction *mov3_ins = assemble_insn(mov3->mnemonic, mov3->op_str, TEXT_ADDRESS, mode);
				Instruction *mov4_ins = assemble_insn(mov4->mnemonic, mov4->op_str, TEXT_ADDRESS, mode);
				Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
				//assemble instructions
				if(!mov1_ins || !mov2_ins || !mov3_ins || !mov4_ins || !sub_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					ListEntry *mov1_entry = ListEntryCreate(mov1_ins);
					ListEntry *mov2_entry = ListEntryCreate(mov2_ins);
					ListEntry *mov3_entry = ListEntryCreate(mov3_ins);
					ListEntry *mov4_entry = ListEntryCreate(mov4_ins);
					ListEntry *sub_entry = ListEntryCreate(sub_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov1_entry);
					ListInsertAfter(list, mov1_entry, mov2_entry);
					ListInsertAfter(list, mov2_entry, mov3_entry);
					ListInsertAfter(list, mov3_entry, mov4_entry);
					ListInsertAfter(list, mov4_entry, sub_entry);
					ListRemove(list, current);
					free(mem_size_indicator);
					free(mov1);
					free(mov2);
					free(mov3);
					free(mov4);
					free(sub);
					optimized = true;
				}
				break;
			}
			//4 = PUSHF
			case 4: {
				//	This instruction cannot be converted into a pair "MOV/SUB", I will handle it in this way:
				//		1) I will create a fake instruction "MOV [MEM], EFLAGS" + "SUB ESP/RSP, 4/8"
				//		2) I will mark the instruction as INVALID, so other optimization methods can ignore it if needed
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *sub = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(sub->mnemonic, "sub");
				uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				uint8_t src_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(mov->op_str, "[%s - %d], %s", cs_reg_name(handle, esp_reg), displacement, cs_reg_name(handle, src_reg));
				sprintf(sub->op_str, "esp, 4");
				char *fake_op_str = calloc(40, sizeof(char));
				sprintf(fake_op_str, "[%s - %d], %s", cs_reg_name(handle, esp_reg), displacement, cs_reg_name(handle, X86_REG_EFLAGS));
				//generating new Instructions
				Instruction *mov_ins = assemble_fake_insn(mov->mnemonic, mov->op_str, fake_op_str, TEXT_ADDRESS, mode);
				Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
				if(!mov_ins || !sub_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//fixing fake operands
					mov_ins->insn->detail->x86.operands[1].reg = X86_REG_EFLAGS;
					//create ListEntry
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *sub_entry = ListEntryCreate(sub_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov_entry);
					ListInsertAfter(list, mov_entry, sub_entry);
					ListRemove(list, current);
					free(fake_op_str);
					free(mov);
					free(sub);
					optimized = true;
				}
				break;
			}
			//8 = PUSHAL
			case 8: {
				switch(mode) {
					case CS_MODE_32: {
						//I have to simulate the push of: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
						cs_insn *mov_eax = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ecx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_edx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ebx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_esp = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ebp = calloc(1, sizeof(cs_insn));
						cs_insn *mov_esi = calloc(1, sizeof(cs_insn));
						cs_insn *mov_edi = calloc(1, sizeof(cs_insn));
						cs_insn *sub = calloc(1, sizeof(cs_insn));
						//generating mnemonic
						sprintf(mov_eax->mnemonic, "mov");
						sprintf(mov_ecx->mnemonic, "mov");
						sprintf(mov_edx->mnemonic, "mov");
						sprintf(mov_ebx->mnemonic, "mov");
						sprintf(mov_esp->mnemonic, "mov");
						sprintf(mov_ebp->mnemonic, "mov");
						sprintf(mov_esi->mnemonic, "mov");
						sprintf(mov_edi->mnemonic, "mov");
						sprintf(sub->mnemonic, "sub");
						//generating op_str
						sprintf(mov_eax->op_str, "[esp-0x20], eax");
						sprintf(mov_ecx->op_str, "[esp-0x1c], ecx");
						sprintf(mov_edx->op_str, "[esp-0x18], edx");
						sprintf(mov_ebx->op_str, "[esp-0x14], ebx");
						sprintf(mov_esp->op_str, "[esp-0x10], esp");
						sprintf(mov_ebp->op_str, "[esp-0xc], ebp");
						sprintf(mov_esi->op_str, "[esp-8], esi");
						sprintf(mov_edi->op_str, "[esp-4], edi");
						sprintf(sub->op_str, "esp, 0x20");
						//generating new Instructions
						Instruction *mov_eax_ins = assemble_insn(mov_eax->mnemonic, mov_eax->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ecx_ins = assemble_insn(mov_ecx->mnemonic, mov_ecx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_edx_ins = assemble_insn(mov_edx->mnemonic, mov_edx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ebx_ins = assemble_insn(mov_ebx->mnemonic, mov_ebx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_esp_ins = assemble_insn(mov_esp->mnemonic, mov_esp->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ebp_ins = assemble_insn(mov_ebp->mnemonic, mov_ebp->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_esi_ins = assemble_insn(mov_esi->mnemonic, mov_esi->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_edi_ins = assemble_insn(mov_edi->mnemonic, mov_edi->op_str, TEXT_ADDRESS, mode);
						Instruction *sub_ins = assemble_insn(sub->mnemonic, sub->op_str, TEXT_ADDRESS, mode);
						//printf("\n[%s %s]\n", mov_eax->mnemonic, mov_eax->op_str);
						//printf("[%s %s]\n", mov_ecx->mnemonic, mov_ecx->op_str);
						//printf("[%s %s]\n", mov_edx->mnemonic, mov_edx->op_str);
						//printf("[%s %s]\n", mov_ebx->mnemonic, mov_ebx->op_str);
						//printf("[%s %s]\n", mov_esp->mnemonic, mov_esp->op_str);
						//printf("[%s %s]\n", mov_ebp->mnemonic, mov_ebp->op_str);
						//printf("[%s %s]\n", mov_esi->mnemonic, mov_esi->op_str);
						//printf("[%s %s]\n", mov_edi->mnemonic, mov_edi->op_str);
						//printf("[%s %s]\n\n", sub->mnemonic, sub->op_str);
						//assemble instructions
						if(!mov_eax_ins || !mov_ebx_ins || !mov_ecx_ins || !mov_edx_ins || !mov_esp_ins || !mov_ebp_ins || !mov_esi_ins || !mov_edi_ins) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							return false;
						} else {
							ListEntry *mov_eax_entry = ListEntryCreate(mov_eax_ins);
							ListEntry *mov_ecx_entry = ListEntryCreate(mov_ecx_ins);
							ListEntry *mov_edx_entry = ListEntryCreate(mov_edx_ins);
							ListEntry *mov_ebx_entry = ListEntryCreate(mov_ebx_ins);
							ListEntry *mov_esp_entry = ListEntryCreate(mov_esp_ins);
							ListEntry *mov_ebp_entry = ListEntryCreate(mov_ebp_ins);
							ListEntry *mov_esi_entry = ListEntryCreate(mov_esi_ins);
							ListEntry *mov_edi_entry = ListEntryCreate(mov_edi_ins);
							ListEntry *sub_entry = ListEntryCreate(sub_ins);
							//add instructions to the list
							ListInsertAfter(list, current, mov_eax_entry);
							ListInsertAfter(list, mov_eax_entry, mov_ecx_entry);
							ListInsertAfter(list, mov_ecx_entry, mov_edx_entry);
							ListInsertAfter(list, mov_edx_entry, mov_ebx_entry);
							ListInsertAfter(list, mov_ebx_entry, mov_esp_entry);
							ListInsertAfter(list, mov_esp_entry, mov_ebp_entry);
							ListInsertAfter(list, mov_ebp_entry, mov_esi_entry);
							ListInsertAfter(list, mov_esi_entry, mov_edi_entry);
							ListInsertAfter(list, mov_edi_entry, sub_entry);
							ListRemove(list, current);
							free(mov_eax);
							free(mov_ecx);
							free(mov_edx);
							free(mov_ebx);
							free(mov_esp);
							free(mov_ebp);
							free(mov_esi);
							free(mov_edi);
							free(sub);
							optimized = true;
						}
						break;
					}
					case CS_MODE_64:
						//the instruction does not exist
						break;
				}
				break;
			}
			//9 = POP REG
			case 9: {
				//retrieving destination size
				uint8_t op_size = 0;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG) {
						op_size = op->size;
					}
				}
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *add = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(add->mnemonic, "add");
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(mov->op_str, "%s, [%s - %d]", insn->op_str, cs_reg_name(handle, esp_reg), op_size);
				sprintf(add->op_str, "%s, %d", cs_reg_name(handle, esp_reg), op_size);
				//generating new Instructions
				Instruction *mov_ins = assemble_insn(mov->mnemonic, mov->op_str, TEXT_ADDRESS, mode);
				Instruction *add_ins = assemble_insn(add->mnemonic, add->op_str, TEXT_ADDRESS, mode);
				//printf("%s %s\n", add->mnemonic, add->op_str);
				//printf("%s %s\n\n", mov->mnemonic, mov->op_str);
				//assemble instructions
				if(!mov_ins || !add_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *add_entry = ListEntryCreate(add_ins);
					//add instructions to the list
					ListInsertAfter(list, current, add_entry);
					ListInsertAfter(list, add_entry, mov_entry);
					ListRemove(list, current);
					free(add);
					free(mov);
					optimized = true;
				}
				break;
			}
			//10 = POP SEG
			case 10: {
				//	This instruction cannot be converted into a pair "MOV/SUB", I will handle it in this way:
				//		1) I will create a fake instruction "ADD ESP/RSP, 4/8" + "MOV SEG, [MEM]"
				//		2) I will mark the instruction as INVALID, so other optimization methods can ignore it if needed
				//retrieve real SEGMENT register
				uint8_t seg_reg = X86_REG_INVALID;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG) {
						seg_reg = op->reg;
					}
				}
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *add = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(add->mnemonic, "add");
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				uint8_t dst_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				sprintf(mov->op_str, "%s, [%s - %d]", cs_reg_name(handle, dst_reg), cs_reg_name(handle, esp_reg), displacement);
				sprintf(add->op_str, "%s, %d", cs_reg_name(handle, esp_reg), displacement);
				char *fake_op_str = calloc(1, sizeof(char));
				sprintf(fake_op_str, "%s, [%s - %d]", cs_reg_name(handle, seg_reg), cs_reg_name(handle, esp_reg), displacement);
				//generating new Instructions
				Instruction *mov_ins = assemble_fake_insn(mov->mnemonic, mov->op_str, fake_op_str, TEXT_ADDRESS, mode);
				Instruction *add_ins = assemble_insn(add->mnemonic, add->op_str, TEXT_ADDRESS, mode);
				//assemble FAKE instruction
				if(!mov_ins || !add_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//fix segment register
					mov_ins->insn->detail->x86.operands[0].reg = seg_reg;
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *add_entry = ListEntryCreate(add_ins);
					//add instructions to the list
					ListInsertAfter(list, current, add_entry);
					ListInsertAfter(list, add_entry, mov_entry);
					ListRemove(list, current);
					free(fake_op_str);
					free(mov);
					free(add);
					optimized = true;
				}
				break;
			}
			//11 = POP [BASE+INDEX*SCALE+DISP]
			case 11: {
				//extract displacement & index from the current instruction
				uint32_t disp = 0, scale = 1, op_size = 0;
				uint8_t index = X86_REG_INVALID, base = X86_REG_INVALID;
				x86 = &(current_insn->insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_MEM) {
						base = op->mem.base;
						index = op->mem.index;
						scale = (uint32_t)op->mem.scale;
						disp = (uint32_t)op->mem.disp;
						op_size = op->size;
					}
				}
				//generating mnemonic & op_str
				cs_insn *mov1 = calloc(1, sizeof(cs_insn));
				cs_insn *mov2 = calloc(1, sizeof(cs_insn));
				cs_insn *mov3 = calloc(1, sizeof(cs_insn));
				cs_insn *mov4 = calloc(1, sizeof(cs_insn));
				cs_insn *add = calloc(1, sizeof(cs_insn));
				sprintf(mov1->mnemonic, "mov");
				sprintf(mov2->mnemonic, "mov");
				sprintf(mov3->mnemonic, "mov");
				sprintf(mov4->mnemonic, "mov");
				sprintf(add->mnemonic, "add");
				uint8_t src_reg;
				char *mem_size_indicator = calloc(20, sizeof(char));
				switch(op_size) {
					case 2:
						sprintf(mem_size_indicator, "word");
						src_reg = X86_REG_AX;
						break;
					case 4:
						sprintf(mem_size_indicator, "dword");
						src_reg = X86_REG_EAX;
						break;
					case 8:
						sprintf(mem_size_indicator, "qword");
						src_reg = X86_REG_RAX;
						break;
				}
				uint8_t tmp_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(mov1->op_str, "[%s - 0x%lx], %s", cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT, cs_reg_name(handle, tmp_reg));
				sprintf(add->op_str, "%s, %d", cs_reg_name(handle, esp_reg), op_size);
				sprintf(mov2->op_str, "%s, %s [%s - %d]", cs_reg_name(handle, src_reg), mem_size_indicator, cs_reg_name(handle, esp_reg), op_size);
				sprintf(mov3->op_str, "%s [%s + %s * 0x%lx + 0x%lx], %s", mem_size_indicator, cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, src_reg));
				sprintf(mov4->op_str, "%s, [%s - 0x%lx]", cs_reg_name(handle, tmp_reg), cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT+op_size);
				//generating new Instructions
				Instruction *mov1_ins = assemble_insn(mov1->mnemonic, mov1->op_str, TEXT_ADDRESS, mode);
				Instruction *mov2_ins = assemble_insn(mov2->mnemonic, mov2->op_str, TEXT_ADDRESS, mode);
				Instruction *mov3_ins = assemble_insn(mov3->mnemonic, mov3->op_str, TEXT_ADDRESS, mode);
				Instruction *mov4_ins = assemble_insn(mov4->mnemonic, mov4->op_str, TEXT_ADDRESS, mode);
				Instruction *add_ins = assemble_insn(add->mnemonic, add->op_str, TEXT_ADDRESS, mode);
				//printf("original: %s %s\n", insn->mnemonic, insn->op_str);
				//printf("%s %s\n", mov1->mnemonic, mov1->op_str);
				//printf("%s %s\n", add->mnemonic, add->op_str);
				//printf("%s %s\n", mov2->mnemonic, mov2->op_str);
				//printf("%s %s\n", mov3->mnemonic, mov3->op_str);
				//printf("%s %s\n\n", mov4->mnemonic, mov4->op_str);
				//assemble instructions
				if(!mov1_ins || !mov2_ins || !mov3_ins || !mov4_ins || !add_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					ListEntry *mov1_entry = ListEntryCreate(mov1_ins);
					ListEntry *mov2_entry = ListEntryCreate(mov2_ins);
					ListEntry *mov3_entry = ListEntryCreate(mov3_ins);
					ListEntry *mov4_entry = ListEntryCreate(mov4_ins);
					ListEntry *add_entry = ListEntryCreate(add_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov1_entry);
					ListInsertAfter(list, mov1_entry, add_entry);
					ListInsertAfter(list, add_entry, mov2_entry);
					ListInsertAfter(list, mov2_entry, mov3_entry);
					ListInsertAfter(list, mov3_entry, mov4_entry);
					ListRemove(list, current);
					free(mem_size_indicator);
					free(mov1);
					free(mov2);
					free(mov3);
					free(mov4);
					free(add);
					optimized = true;
				}
				break;
			}
			//12 = POPF
			case 12: {
				//	This instruction cannot be converted into a pair "MOV/SUB", I will handle it in this way:
				//		1) I will create a fake instruction "ADD ESP/RSP, 4/8" + "MOV EFLAGS, [MEM]"
				//		2) I will mark the instruction as INVALID, so other optimization methods can ignore it if needed
				//generating mnemonic & op_str
				cs_insn *mov = calloc(1, sizeof(cs_insn));
				cs_insn *add = calloc(1, sizeof(cs_insn));
				sprintf(mov->mnemonic, "mov");
				sprintf(add->mnemonic, "add");
				uint8_t dst_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				uint8_t displacement = (mode == CS_MODE_32) ? 4 : 8;
				sprintf(mov->op_str, "%s, [%s - %d]", cs_reg_name(handle, dst_reg), cs_reg_name(handle, esp_reg), displacement);
				sprintf(add->op_str, "%s, %d", cs_reg_name(handle, esp_reg), displacement);
				char *fake_op_str = calloc(40, sizeof(char));
				sprintf(fake_op_str, "%s, [%s - %d]", cs_reg_name(handle, X86_REG_EFLAGS), cs_reg_name(handle, esp_reg), displacement);
				//generating new Instructions
				Instruction *mov_ins = assemble_fake_insn(mov->mnemonic, mov->op_str, fake_op_str, TEXT_ADDRESS, mode);
				Instruction *add_ins = assemble_insn(add->mnemonic, add->op_str, TEXT_ADDRESS, mode);
				//assemble FAKE instruction
				if(!mov_ins || !add_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//fix eflags register
					mov_ins->insn->detail->x86.operands[0].reg = X86_REG_EFLAGS;
					ListEntry *mov_entry = ListEntryCreate(mov_ins);
					ListEntry *add_entry = ListEntryCreate(add_ins);
					//add instructions to the list
					ListInsertAfter(list, current, add_entry);
					ListInsertAfter(list, add_entry, mov_entry);
					free(fake_op_str);
					free(mov);
					free(add);
					optimized = true;
				}
				break;
			}
			//16 = POPAL
			case 16: {
				switch(mode) {
					case CS_MODE_32: {
						//I have to simulate the pop of: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
						cs_insn *mov_eax = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ecx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_edx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ebx = calloc(1, sizeof(cs_insn));
						cs_insn *mov_esp = calloc(1, sizeof(cs_insn));
						cs_insn *mov_ebp = calloc(1, sizeof(cs_insn));
						cs_insn *mov_esi = calloc(1, sizeof(cs_insn));
						cs_insn *mov_edi = calloc(1, sizeof(cs_insn));
						cs_insn *add = calloc(1, sizeof(cs_insn));
						//generating mnemonic
						sprintf(mov_eax->mnemonic, "mov");
						sprintf(mov_ecx->mnemonic, "mov");
						sprintf(mov_edx->mnemonic, "mov");
						sprintf(mov_ebx->mnemonic, "mov");
						sprintf(mov_esp->mnemonic, "mov");
						sprintf(mov_ebp->mnemonic, "mov");
						sprintf(mov_esi->mnemonic, "mov");
						sprintf(mov_edi->mnemonic, "mov");
						sprintf(add->mnemonic, "add");
						//generating op_str
						sprintf(add->op_str, "esp, 0x20");
						sprintf(mov_edi->op_str, "edi, [esp-4]");
						sprintf(mov_esi->op_str, "esi, [esp-8]");
						sprintf(mov_ebp->op_str, "ebp, [esp-0xc]");
						sprintf(mov_esp->op_str, "esp, [esp-0x10]");
						sprintf(mov_ebx->op_str, "ebx, [esp-0x14]");
						sprintf(mov_edx->op_str, "edx, [esp-0x18]");
						sprintf(mov_ecx->op_str, "ecx, [esp-0x1c]");
						sprintf(mov_eax->op_str, "eax, [esp-0x20]");
						//generating new Instructions
						Instruction *mov_eax_ins = assemble_insn(mov_eax->mnemonic, mov_eax->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ecx_ins = assemble_insn(mov_ecx->mnemonic, mov_ecx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_edx_ins = assemble_insn(mov_edx->mnemonic, mov_edx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ebx_ins = assemble_insn(mov_ebx->mnemonic, mov_ebx->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_esp_ins = assemble_insn(mov_esp->mnemonic, mov_esp->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_ebp_ins = assemble_insn(mov_ebp->mnemonic, mov_ebp->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_esi_ins = assemble_insn(mov_esi->mnemonic, mov_esi->op_str, TEXT_ADDRESS, mode);
						Instruction *mov_edi_ins = assemble_insn(mov_edi->mnemonic, mov_edi->op_str, TEXT_ADDRESS, mode);
						Instruction *add_ins = assemble_insn(add->mnemonic, add->op_str, TEXT_ADDRESS, mode);
						//printf("original: %s %s\n", insn->mnemonic, insn->op_str);
						//printf("[%s %s]\n", add->mnemonic, add->op_str);
						//printf("[%s %s]\n", mov_eax->mnemonic, mov_eax->op_str);
						//printf("[%s %s]\n", mov_ecx->mnemonic, mov_ecx->op_str);
						//printf("[%s %s]\n", mov_edx->mnemonic, mov_edx->op_str);
						//printf("[%s %s]\n", mov_ebx->mnemonic, mov_ebx->op_str);
						//printf("[%s %s]\n", mov_esp->mnemonic, mov_esp->op_str);
						//printf("[%s %s]\n", mov_ebp->mnemonic, mov_ebp->op_str);
						//printf("[%s %s]\n", mov_esi->mnemonic, mov_esi->op_str);
						//printf("[%s %s]\n\n", mov_edi->mnemonic, mov_edi->op_str);
						//assemble instructions
						if(!mov_eax_ins || !mov_ebx_ins || !mov_ecx_ins || !mov_edx_ins || !mov_esp_ins || !mov_ebp_ins || !mov_esi_ins || !mov_edi_ins || !add_ins) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							return false;
						} else {
							ListEntry *mov_eax_entry = ListEntryCreate(mov_eax_ins);
							ListEntry *mov_ecx_entry = ListEntryCreate(mov_ecx_ins);
							ListEntry *mov_edx_entry = ListEntryCreate(mov_edx_ins);
							ListEntry *mov_ebx_entry = ListEntryCreate(mov_ebx_ins);
							ListEntry *mov_esp_entry = ListEntryCreate(mov_esp_ins);
							ListEntry *mov_ebp_entry = ListEntryCreate(mov_ebp_ins);
							ListEntry *mov_esi_entry = ListEntryCreate(mov_esi_ins);
							ListEntry *mov_edi_entry = ListEntryCreate(mov_edi_ins);
							ListEntry *add_entry = ListEntryCreate(add_ins);
							//add instructions to the list
							ListInsertAfter(list, current, add_entry);
							ListInsertAfter(list, add_entry, mov_eax_entry);
							ListInsertAfter(list, mov_eax_entry, mov_ecx_entry);
							ListInsertAfter(list, mov_ecx_entry, mov_edx_entry);
							ListInsertAfter(list, mov_edx_entry, mov_ebx_entry);
							ListInsertAfter(list, mov_ebx_entry, mov_esp_entry);
							ListInsertAfter(list, mov_esp_entry, mov_ebp_entry);
							ListInsertAfter(list, mov_ebp_entry, mov_esi_entry);
							ListInsertAfter(list, mov_esi_entry, mov_edi_entry);
							ListRemove(list, current);
							free(mov_eax);
							free(mov_ecx);
							free(mov_edx);
							free(mov_ebx);
							free(mov_esp);
							free(mov_ebp);
							free(mov_esi);
							free(mov_edi);
							free(add);
							optimized = true;
						}
						break;
					}
				}
				break;
			}
			//17 = MOV REG, ESP/RSP
			case 17: {
				//generating mnemonic & op_str
				cs_insn *lea = calloc(1, sizeof(cs_insn));
				sprintf(lea->mnemonic, "lea");
				//find destination register
				uint8_t dst_reg = get_reg_at(current_insn, REG_FIRST);
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(lea->op_str, "%s, [%s]", cs_reg_name(handle, dst_reg), cs_reg_name(handle, esp_reg));
				//generating new Instructions
				Instruction *lea_ins = assemble_insn(lea->mnemonic, lea->op_str, TEXT_ADDRESS, mode);
				//printf("%s %s\n\n", lea->mnemonic, lea->op_str);
				//assemble instructions
				if(!lea_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					ListEntry *lea_entry = ListEntryCreate(lea_ins);
					ListInsertAfter(list, current, lea_entry);
					ListRemove(list, current);
					free(lea);
					optimized = true;
				}
				break;
			}
			//18 = MOV [BASE+INDEX*SCALE+DISP], ESP/RSP
			case 18: {
				//extract index, scale, & displacement from the current instruction
				uint8_t base = get_base(current_insn);
				uint8_t index = get_index(current_insn);
				uint32_t disp;
				get_disp(current_insn, &disp);
				uint32_t scale;
				get_scale(current_insn, &scale);
				//generating mnemonic & op_str
				cs_insn *mov1 = calloc(1, sizeof(cs_insn));
				cs_insn *lea = calloc(1, sizeof(cs_insn));
				cs_insn *mov2 = calloc(1, sizeof(cs_insn));
				cs_insn *mov3 = calloc(1, sizeof(cs_insn));
				sprintf(mov1->mnemonic, "mov");
				sprintf(lea->mnemonic, "lea");
				sprintf(mov2->mnemonic, "mov");
				sprintf(mov3->mnemonic, "mov");
				//generating op_str
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				uint8_t tmp_reg = (mode == CS_MODE_32) ? X86_REG_EAX : X86_REG_RAX;
				sprintf(mov1->op_str, "[%s - 0x%lx], %s", cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT, cs_reg_name(handle, tmp_reg));
				sprintf(lea->op_str, "%s, [%s]", cs_reg_name(handle, tmp_reg), cs_reg_name(handle, esp_reg));
				sprintf(mov2->op_str, "[%s + %s * 0x%lx + 0x%lx], %s", cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, tmp_reg));
				sprintf(mov3->op_str, "%s, [%s - 0x%lx]", cs_reg_name(handle, tmp_reg), cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT);
				//generating new Instructions
				Instruction *mov1_ins = assemble_insn(mov1->mnemonic, mov1->op_str, TEXT_ADDRESS, mode);
				Instruction *lea_ins = assemble_insn(lea->mnemonic, lea->op_str, TEXT_ADDRESS, mode);
				Instruction *mov2_ins = assemble_insn(mov2->mnemonic, mov2->op_str, TEXT_ADDRESS, mode);
				Instruction *mov3_ins = assemble_insn(mov3->mnemonic, mov3->op_str, TEXT_ADDRESS, mode);
				//printf("original: %s %s\n", insn->mnemonic, insn->op_str);
				//printf("%s %s\n", mov1->mnemonic, mov1->op_str);
				//printf("%s %s\n", lea->mnemonic, lea->op_str);
				//printf("%s %s\n", mov2->mnemonic, mov2->op_str);
				//printf("%s %s\n\n", mov3->mnemonic, mov3->op_str);
				//assemble instructions
				if(!mov1_ins || !mov2_ins || !mov3_ins || !lea_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//add instructions to the list
					ListEntry *mov1_entry = ListEntryCreate(mov1_ins);
					ListEntry *mov2_entry = ListEntryCreate(mov2_ins);
					ListEntry *mov3_entry = ListEntryCreate(mov3_ins);
					ListEntry *lea_entry = ListEntryCreate(lea_ins);
					ListInsertAfter(list, current, mov1_entry);
					ListInsertAfter(list, mov1_entry, lea_entry);
					ListInsertAfter(list, lea_entry, mov2_entry);
					ListInsertAfter(list, mov2_entry, mov3_entry);
					ListRemove(list, current);
					free(mov1);
					free(mov2);
					free(mov3);
					free(lea);
					optimized = true;
				}
				break;
			}
			//19 = XCHG [BASE+INDEX*SCALE+DISP], REG
			case 19: {
				//find destination register
				uint8_t reg = X86_REG_INVALID, base = X86_REG_INVALID, index = X86_REG_INVALID;
				uint32_t scale = 1, disp = 0;
				uint64_t old_address = current_insn->insn->address;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG && op->reg != X86_REG_INVALID && (op->reg != X86_REG_ESP && op->reg != X86_REG_RSP)) {
						reg = op->reg;
					} else if(op->type == X86_OP_MEM) {
						base = op->mem.base;
						index = op->mem.index;
						scale = (uint32_t)op->mem.scale;
						disp = (uint32_t)op->mem.disp;
					}
				}
				//choose temporary register
				uint8_t temp_reg = X86_REG_INVALID;
				switch(mode) {
					case CS_MODE_32:
						temp_reg = (reg == X86_REG_EAX) ? X86_REG_EBX : X86_REG_EAX;
						break;
					case CS_MODE_64:
						temp_reg = (reg == X86_REG_RAX) ? X86_REG_RBX : X86_REG_RAX;
						break;
				}
				//generating mnemonic & op_str
				cs_insn *mov1 = calloc(1, sizeof(cs_insn));
				cs_insn *mov2 = calloc(1, sizeof(cs_insn));
				cs_insn *mov3 = calloc(1, sizeof(cs_insn));
				cs_insn *mov4 = calloc(1, sizeof(cs_insn));
				cs_insn *mov5 = calloc(1, sizeof(cs_insn));
				sprintf(mov1->mnemonic, "mov");
				sprintf(mov2->mnemonic, "mov");
				sprintf(mov3->mnemonic, "mov");
				sprintf(mov4->mnemonic, "mov");
				sprintf(mov5->mnemonic, "mov");
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(mov1->op_str, "[%s - 0x%lx], %s", cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT, cs_reg_name(handle, temp_reg));
				sprintf(mov2->op_str, "%s, [%s + %s * 0x%lx + 0x%lx]", cs_reg_name(handle, temp_reg), cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp);
				sprintf(mov3->op_str, "[%s + %s * 0x%lx + 0x%lx], %s",  cs_reg_name(handle, base), cs_reg_name(handle, index), scale, disp, cs_reg_name(handle, reg));
				sprintf(mov4->op_str, "%s, %s", cs_reg_name(handle, reg), cs_reg_name(handle, temp_reg));
				sprintf(mov5->op_str, "%s, [%s - 0x%lx]", cs_reg_name(handle, temp_reg), cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT);
				//generating new Instructions
				Instruction *mov1_ins = assemble_insn(mov1->mnemonic, mov1->op_str, TEXT_ADDRESS, mode);
				Instruction *mov2_ins = assemble_insn(mov2->mnemonic, mov2->op_str, TEXT_ADDRESS, mode);
				Instruction *mov3_ins = assemble_insn(mov3->mnemonic, mov3->op_str, TEXT_ADDRESS, mode);
				Instruction *mov4_ins = assemble_insn(mov4->mnemonic, mov4->op_str, TEXT_ADDRESS, mode);
				Instruction *mov5_ins = assemble_insn(mov5->mnemonic, mov5->op_str, TEXT_ADDRESS, mode);
				//printf("%s %s\n", mov1->mnemonic, mov1->op_str);
				//printf("%s %s\n", mov2->mnemonic, mov2->op_str);
				//printf("%s %s\n", mov3->mnemonic, mov3->op_str);
				//printf("%s %s\n", mov4->mnemonic, mov4->op_str);
				//printf("%s %s\n\n", mov5->mnemonic, mov5->op_str);
				//assemble instructions
				if(!mov1_ins || !mov2_ins || !mov3_ins || !mov4_ins || !mov5_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//update addresses
					mov1_ins->insn->address = old_address++;
					mov2_ins->insn->address = old_address++;
					mov3_ins->insn->address = old_address++;
					mov4_ins->insn->address = old_address++;
					mov5_ins->insn->address = old_address;
					//create ListEntry
					ListEntry *mov1_entry = ListEntryCreate(mov1_ins);
					ListEntry *mov2_entry = ListEntryCreate(mov2_ins);
					ListEntry *mov3_entry = ListEntryCreate(mov3_ins);
					ListEntry *mov4_entry = ListEntryCreate(mov4_ins);
					ListEntry *mov5_entry = ListEntryCreate(mov5_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov1_entry);
					ListInsertAfter(list, mov1_entry, mov2_entry);
					ListInsertAfter(list, mov2_entry, mov3_entry);
					ListInsertAfter(list, mov3_entry, mov4_entry);
					ListInsertAfter(list, mov4_entry, mov5_entry);
					ListRemove(list, current);
					free(mov1);
					free(mov2);
					free(mov3);
					free(mov4);
					free(mov5);
					optimized = true;
				}
				break;
			}
			//20 = XCHG REG1, REG2
			case 20: {
				//find source & destination registers
				uint8_t src_reg = X86_REG_INVALID, dst_reg = X86_REG_INVALID;
				uint64_t old_address = current_insn->insn->address;
				x86 = &(insn->detail->x86);
				op_count = x86->op_count;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG && op->reg != X86_REG_INVALID && (op->reg != X86_REG_ESP && op->reg != X86_REG_RSP)) {
						if(dst_reg == X86_REG_INVALID) {
							//extract destination reg
							dst_reg = op->reg;
						} else {
							//extract source reg
							src_reg = op->reg;
						}
					}
				}
				//check if src_reg == dst_reg, in this case
				//generating mnemonic & op_str
				cs_insn *mov1 = calloc(1, sizeof(cs_insn));
				cs_insn *mov2 = calloc(1, sizeof(cs_insn));
				cs_insn *mov3 = calloc(1, sizeof(cs_insn));
				sprintf(mov1->mnemonic, "mov");
				sprintf(mov2->mnemonic, "mov");
				sprintf(mov3->mnemonic, "mov");
				uint8_t esp_reg = (mode == CS_MODE_32) ? X86_REG_ESP : X86_REG_RSP;
				sprintf(mov1->op_str, "[%s - 0x%lx], %s", cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT, cs_reg_name(handle, src_reg));
				sprintf(mov2->op_str, "%s, %s", cs_reg_name(handle, src_reg), cs_reg_name(handle, dst_reg));		
				sprintf(mov3->op_str, "%s, [%s - 0x%lx]", cs_reg_name(handle, dst_reg), cs_reg_name(handle, esp_reg), STACK_DISPLACEMENT);
				//generating new Instructions
				Instruction *mov1_ins = assemble_insn(mov1->mnemonic, mov1->op_str, TEXT_ADDRESS, mode);
				Instruction *mov2_ins = assemble_insn(mov2->mnemonic, mov2->op_str, TEXT_ADDRESS, mode);
				Instruction *mov3_ins = assemble_insn(mov3->mnemonic, mov3->op_str, TEXT_ADDRESS, mode);
				//printf("%s %s\n", mov1->mnemonic, mov1->op_str);
				//printf("%s %s\n", mov2->mnemonic, mov2->op_str);
				//printf("%s %s\n\n", mov3->mnemonic, mov3->op_str);
				if(!mov1_ins || !mov2_ins || !mov3_ins) {
					if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
					return false;
				} else {
					//update addresses
					mov1_ins->insn->address = old_address++;
					mov2_ins->insn->address = old_address++;
					mov3_ins->insn->address = old_address;
					//create ListEntry
					ListEntry *mov1_entry = ListEntryCreate(mov1_ins);
					ListEntry *mov2_entry = ListEntryCreate(mov2_ins);
					ListEntry *mov3_entry = ListEntryCreate(mov3_ins);
					//add instructions to the list
					ListInsertAfter(list, current, mov1_entry);
					ListInsertAfter(list, mov1_entry, mov2_entry);
					ListInsertAfter(list, mov2_entry, mov3_entry);
					ListRemove(list, current);
					free(mov1);
					free(mov2);
					free(mov3);
					optimized = true;
				}
				break;
			}
			//21 = LEA REG, [BASE+INDEX*SCALE+DISP]
			case 21: {
				cs_x86 *x86 = &(current_insn->insn->detail->x86);
				cs_x86_op *op;
				size_t op_count = x86->op_count;
				//extract useful information
				uint8_t reg = X86_REG_INVALID, base = X86_REG_INVALID, index = X86_REG_INVALID;
				uint32_t scale = 1, disp = 0;
				for(size_t i = 0; i < op_count; i++) {
					op = &(x86->operands[i]);
					if(op->type == X86_OP_REG && op->access == CS_AC_WRITE) {
						reg = op->reg;
					} else if(op->type == X86_OP_MEM && op->access == CS_AC_READ) {
						base = op->mem.base;
						index = op->mem.index;
						scale = (uint32_t)op->mem.scale;
						disp = (uint32_t)op->mem.disp;
					}
				}
				if(!is_same_register_type(base, X86_REG_RSP) && !is_same_register_type(index, X86_REG_RSP) && !is_same_register_type(base, X86_REG_RIP) && !is_same_register_type(index, X86_REG_RIP)) {
					//create new instructions for expansion
					if(base != X86_REG_INVALID && index != X86_REG_INVALID) {
						//printf("Found: lea reg, [reg1 + reg2*scale + disp]: %s %s\n", current->insn->mnemonic, current->insn->op_str);
						//Need to implement:
						//shl index, scale
						//add base, index
						//add base, disp
						//mov reg, base
						if(scale != 1) {
							//shl index, scale
							Instruction *shl_ins = calloc(1, sizeof(Instruction));
							shl_ins->insn = calloc(1, sizeof(cs_insn));
							sprintf(shl_ins->insn->mnemonic, "shl");
							//in this case the 'scale' value can be: 0x2 (0x1), 0x4 (0x2), 0x8 (0x3)
							switch(scale) {
								case 0x2:
									scale = 1;
									break;
								case 0x4:
									scale = 2;
									break;
								case 0x8:
									scale = 3;
									break;
							}
							sprintf(shl_ins->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, index), scale);
							if(!(reassemble(shl_ins, mode) && update_disasm(shl_ins, TEXT_ADDRESS, mode))) {
								if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							} else {
								//printf("SHL: %s %s\n", shl_ins->insn->mnemonic, shl_ins->insn->op_str);
								ListEntry *shl_entry = ListEntryCreate(shl_ins);
								ListInsertBefore(list, current, shl_entry);
							}
						}
						ListEntry *add_entry_1;
						Instruction *add_ins_1 = calloc(1, sizeof(Instruction));
						add_ins_1->insn = calloc(1, sizeof(cs_insn));
						sprintf(add_ins_1->insn->mnemonic, "add");
						sprintf(add_ins_1->insn->op_str, "%s, %s", cs_reg_name(handle, base), cs_reg_name(handle, index));
						if(!(reassemble(add_ins_1, mode) && update_disasm(add_ins_1, TEXT_ADDRESS, mode))) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
						} else {
							//printf("ADD: %s %s\n", add_ins_1->insn->mnemonic, add_ins_1->insn->op_str);
							ListEntry *add_entry_1 = ListEntryCreate(add_ins_1);
							ListInsertAfter(list, current, add_entry_1);
						}
						if(disp != 0) {
							Instruction *add_ins_2 = calloc(1, sizeof(Instruction));
							add_ins_2->insn = calloc(1, sizeof(cs_insn));
							sprintf(add_ins_2->insn->mnemonic, "add");
							sprintf(add_ins_2->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, base), disp);
							if(!(reassemble(add_ins_2, mode) && update_disasm(add_ins_2, TEXT_ADDRESS, mode))) {
								if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							} else {
								//printf("ADD: %s %s\n", add_ins_2->insn->mnemonic, add_ins_2->insn->op_str);
								ListEntry *add_entry_2 = ListEntryCreate(add_ins_2);
								ListInsertAfter(list, add_entry_1, add_entry_2);
							}
						}
						Instruction *mov_ins = calloc(1, sizeof(Instruction));
						mov_ins->insn = calloc(1, sizeof(cs_insn));
						sprintf(mov_ins->insn->mnemonic, "mov");
						sprintf(mov_ins->insn->op_str, "%s, %s", cs_reg_name(handle, reg), cs_reg_name(handle, base));
						if(!(reassemble(mov_ins, mode) && update_disasm(mov_ins, TEXT_ADDRESS, mode))) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
						} else {
							//printf("MOV: %s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
							ListEntry *mov_entry = ListEntryCreate(mov_ins);
							ListInsertBefore(list, current->next, mov_entry);
						}
						ListRemove(list, current);
						optimized = true;
					} else if(base != X86_REG_INVALID) {
						//printf("Found: lea reg, [reg1 + disp]: %s %s\n", current->insn->mnemonic, current->insn->op_str);
						//Need to implement
						//add base, disp
						//mov reg, base
						if(disp != 0) {
							Instruction *add_ins_2 = calloc(1, sizeof(Instruction));
							add_ins_2->insn = calloc(1, sizeof(cs_insn));
							sprintf(add_ins_2->insn->mnemonic, "add");
							sprintf(add_ins_2->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, base), disp);
							if(!(reassemble(add_ins_2, mode) && update_disasm(add_ins_2, TEXT_ADDRESS, mode))) {
								if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							} else {
								//printf("ADD: %s %s\n", add_ins_2->insn->mnemonic, add_ins_2->insn->op_str);
								ListEntry *add_entry_2 = ListEntryCreate(add_ins_2);
								ListInsertBefore(list, current, add_entry_2);
							}
						}
						Instruction *mov_ins = calloc(1, sizeof(Instruction));
						mov_ins->insn = calloc(1, sizeof(cs_insn));
						sprintf(mov_ins->insn->mnemonic, "mov");
						sprintf(mov_ins->insn->op_str, "%s, %s", cs_reg_name(handle, reg), cs_reg_name(handle, base));
						if(!(reassemble(mov_ins, mode) && update_disasm(mov_ins, TEXT_ADDRESS, mode))) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
						} else {
							//printf("MOV: %s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
							//ListInsertAfter(list, current, mov_ins);
							uint64_t old_address = insn->address;
							memcpy(insn, mov_ins->insn, sizeof(cs_insn));
							insn->address = old_address;
							//ListRemove(list, current);
							optimized = true;
						}
					} else if(index != X86_REG_INVALID) {
						//printf("Found: lea reg, [reg2*scale + disp]: %s %s\n", current->insn->mnemonic, current->insn->op_str);
						//Need to implement
						//shl index, scale
						//add index, disp
						//mov reg, index
						Instruction *shl_ins;
						ListEntry *shl_entry;
						if(scale != 1) {
							//shl index, scale
							shl_ins = calloc(1, sizeof(Instruction));
							shl_ins->insn = calloc(1, sizeof(cs_insn));
							sprintf(shl_ins->insn->mnemonic, "shl");
							//in this case the 'scale' value can be: 0x2 (0x1), 0x4 (0x2), 0x8 (0x3)
							switch(scale) {
								case 0x2:
									scale = 1;
									break;
								case 0x4:
									scale = 2;
									break;
								case 0x8:
									scale = 3;
									break;
							}
							sprintf(shl_ins->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, index), scale);
							if(!(reassemble(shl_ins, mode) && update_disasm(shl_ins, TEXT_ADDRESS, mode))) {
								if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							} else {
								//printf("SHL: %s %s\n", shl_ins->insn->mnemonic, shl_ins->insn->op_str);
								shl_entry = ListEntryCreate(shl_ins);
								ListInsertBefore(list, current, shl_entry);
							}
						}
						if(disp != 0) {
							Instruction *add_ins_2 = calloc(1, sizeof(Instruction));
							add_ins_2->insn = calloc(1, sizeof(cs_insn));
							sprintf(add_ins_2->insn->mnemonic, "add");
							sprintf(add_ins_2->insn->op_str, "%s, 0x%lx", cs_reg_name(handle, index), disp);
							if(!(reassemble(add_ins_2, mode) && update_disasm(add_ins_2, TEXT_ADDRESS, mode))) {
								if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
							} else {
								//printf("ADD: %s %s\n", add_ins_2->insn->mnemonic, add_ins_2->insn->op_str);
								if(shl_ins == NULL) {
									ListEntry *add_entry_2 = ListEntryCreate(add_ins_2);
									ListInsertBefore(list, current, add_entry_2);
								} else {
									ListEntry *add_entry_2 = ListEntryCreate(add_ins_2);
									ListInsertAfter(list, shl_entry, add_entry_2);
								}
							}
						}
						Instruction *mov_ins = calloc(1, sizeof(Instruction));
						mov_ins->insn = calloc(1, sizeof(cs_insn));
						sprintf(mov_ins->insn->mnemonic, "mov");
						sprintf(mov_ins->insn->op_str, "%s, %s", cs_reg_name(handle, reg), cs_reg_name(handle, index));
						if(!(reassemble(mov_ins, mode) && update_disasm(mov_ins, TEXT_ADDRESS, mode))) {
							if(VERBOSE_ERROR) printf("[-] Error: reassemble() || update_disasm() - expand_stack_ins\n");
						} else {
							//printf("MOV: %s %s\n", mov_ins->insn->mnemonic, mov_ins->insn->op_str);
							ListEntry *mov_entry = ListEntryCreate(mov_ins);
							ListInsertAfter(list, current, mov_entry);
						}
						ListRemove(list, current);
						optimized = true;
					}
				}
				break;
			}
		}
		current = next;
	}
	return optimized;
}

/* ------------------------------------------------------------------------------------------------------------------ */

/*
	Name: update_add_sub
	Description: this function calculates the new value of a sub/add instruction an saves it on imm3;
	it returns also the ID for the updated instruction, ADD or SUB.
*/
static uint32_t update_add_sub(bool is_add_1, uint64_t imm1, bool is_add_2, uint64_t imm2, uint64_t *imm3) {
	bool is_add;
	if(is_add_1 == is_add_2) {
		*imm3 = imm1 + imm2;
		is_add = is_add_1;
	} else {
		if(is_add_1 && !is_add_2) {
			if((int64_t)imm1 > (int64_t)imm2) {
				*imm3 = imm1 - imm2;
				is_add = is_add_1;
			} else {
				*imm3 = imm2 - imm1;
				is_add = is_add_2;
			}
		} else {
			if((int64_t)imm1 > (int64_t)imm2) {
				*imm3 = imm1 - imm2;
				is_add = is_add_1;
			} else {
				*imm3 = imm2 - imm1;
				is_add = is_add_2;
			}
		}
	}
	return (is_add) ? X86_INS_ADD : X86_INS_SUB;
}

/*
	Name: collapse_add_sub
	Description: this function is used to collapse add & sub
	instructions on registers & memory locations, for example:
		add reg, 0x2 			add [mem], 0x4
		sub reg, 0x4 			sub [mem], 0x2
		------------ 			--------------
		sub reg, 0x2 			add [mem], 0x2
	It is possible to semplificate also the following case,
	because add/sub operations are not interfering:
		add reg1, 0x4
		add reg1, reg2
		sub reg1, 0x2
		-------------
		add reg1, reg2
		add reg1, 0x2
	In the collapse operation must stop when the register or the
	memory location is accessed by an instruction different from
	add or sub, for example:
		add reg, 0x4
		xor reg, 0x7
		sub reg, 0x2
	The xor operation blocks the collapse.
	The memory collapse must stop also when 'base'/'index' are
	modified during propagation.
*/
bool collapse_add_sub(csh handle, List *list, uint8_t mode) {
	bool optimized = false;
	//check if the list is empty
	if(!list->first) return false;
	ListEntry *current = list->first, *next;
	//mask for general ADD REG, IMM match
	InsnMatch add_reg = { .id = X86_INS_ADD, .type = X86_DST_REG_SRC_IMM };
	//mask for general ADD [MEM], IMM match
	InsnMatch add_mem = { .id = X86_INS_ADD, .type = X86_DST_MEM_SRC_IMM };
	//mask for general SUB REG, IMM
	InsnMatch sub_reg = { .id = X86_INS_SUB, .type = X86_DST_REG_SRC_IMM };
	//mask for general SUB [MEM], IMM
	InsnMatch sub_mem = { .id = X86_INS_SUB, .type = X86_DST_MEM_SRC_IMM };
	//pointers to add/sub instructions
	ListEntry *reg_before, *mem_before, *first;
	Instruction *first_insn;
	while(current) {
		//check who comes first between add_reg - sub_reg & add_mem - sub_mem
		reg_before = ListIsBefore(find_insn(current, NULL, &add_reg), find_insn(current, NULL, &sub_reg));
		mem_before = ListIsBefore(find_insn(current, NULL, &add_mem), find_insn(current, NULL, &sub_mem));
		//check who comes first between reg_before & mem_before
		first = ListIsBefore(reg_before, mem_before);
		if(!first/* || first == list->last*/) {
			//The are no more add/sub instructions involving immediates in the code
			if(VERBOSE) printf("[I] collapse_add_sub end!\n");
			break;
		}
		//extract Instruction from ListEntry
		first_insn = (Instruction *)first->content;
		if(VERBOSE) print_insn("\n[I] The ADD/SUB instruction is: ", first_insn);
		//the next search will start right after this 'first' instruction
		next = first->next;
		if(is_memory_insn(first_insn)) {
			//this is a memory instruction, need to understand how to handle the case:
			//add [mem], imm
			//sub [mem], imm
		} else {
			//this is a register instruction, extract the destination register and the immediate
			uint8_t reg = get_reg_at(first_insn, REG_FIRST);
			uint64_t imm;
			bool imm_found = get_imm(first_insn, &imm);
			//check if the register & imm are valid
			if(is_valid(reg) && imm_found) {
				//the instruction is valid, check if the mnemonic is add or sub
				bool is_add = (cmp_id(first_insn->insn->id, X86_INS_ADD)) ? true : false;
				ListEntry *next_use = first;
				Instruction *instruction;
				InsnAccess reg_access = { .reg = reg, .op_type = X86_OP_REG };
				//find the next instruction using REG
				while(next_use && next_use->next && (next_use = find_insn_op_general_access(next_use->next, NULL, &reg_access))) {
					instruction = (Instruction *)next_use->content;
					//check if the instruction is a memory instruction
					if(is_memory_insn(instruction)) {
						if(VERBOSE) print_insn("[I] mem: ", instruction);
						uint8_t base = get_base(instruction);
						uint8_t index = get_index(instruction);
						uint8_t dst_reg = get_reg_at(instruction, REG_FIRST);
						uint8_t src_reg = get_reg_at(instruction, REG_SECOND);
						uint32_t id = get_id(instruction);
						//check if 'reg' is used as index, terminate loop
						if(is_same_register_type(index, reg) && !is_same_register_type(base, reg)) {
							next_use = NULL;
						} else if(is_same_register_type(base, reg)) {
							//check if 'reg' is used as base, update disp in case
							//update the displacement
							uint32_t disp;
							get_disp(instruction, &disp);
							uint64_t imm3;
							uint32_t new_opcode = update_add_sub(is_add, imm, true, disp, &imm3);
							disp = (new_opcode == X86_INS_ADD) ? (uint32_t)imm3 : (uint32_t)(-imm3);
							//update the instruction
							if(set_disp(instruction, disp)) {
								//reassemble the instruction
								/*Instruction *updated = update_insn_str(handle, instruction, mode);
								ListChangeEntry(next_use, updated);
								//move 'first' instruction under the updated memory instruction and start again
								ListRemove(list, first);
								ListInsertAfter(list, next_use, first);
								printf("AFTER\n");
								print_disassembly(handle, list, INFO);
								if(VERBOSE && next_use) print_insn("next_use: ", next_use->content);
								if(VERBOSE && next_use->next) print_insn("next_use->next: ", next_use->next->content);
								if(VERBOSE && next_use->prev) print_insn("next_use->prev: ", next_use->prev->content);
								if(VERBOSE && first) print_insn("next_use: ", first->content);
								if(VERBOSE && first->next) print_insn("first->next: ", first->next->content);
								if(VERBOSE && first->prev) print_insn("first->prev: ", first->prev->content);
								//mark as optimized & start a new loop
								optimized = true;
								//stop here if the end is reached
								/*if(first->next == list->last) {	
									first->next = NULL;
									return optimized;
								}*/
								//next_use = NULL;
							} else {
								printf("[!] Error while setting displacement, exit!\n");
								ExitProcess(EXIT_FAILURE);
							}
						}
						//check if the source or destination register is equal to 'reg'
						if(is_same_register_type(reg, dst_reg)) {
							//in particular check for MOV overwrite, in this case delete also 'first'
							if(cmp_id(id, X86_INS_MOV)) {
								print_insn("OVERWRITE: ", first_insn);
								ListRemove(list, first);
								free(first->content);
							}
							//check if 'reg' is used as destination, terminate loop
							next_use = NULL;
						} else if(is_same_register_type(reg, src_reg)) {
							print_insn("READ: ", first_insn);
							next_use = NULL;
						}
					} else {
						//check if the instruction is ADD/SUB
						if(cmp_id(instruction->insn->id, X86_INS_ADD) || cmp_id(instruction->insn->id, X86_INS_SUB)) {
							//found an add/sub instruction, check if the destination register is 'reg'
							if(is_same_register_type(get_reg_at(instruction, REG_FIRST), reg)) {
								//check if it is using an imm value
								uint64_t tmp_imm;
								if(get_imm(instruction, &tmp_imm)) {
									if(VERBOSE) print_insn("[I] reg->add/sub->imm: ", instruction);
									//update the immediate
									bool is_add_2 = (cmp_id(instruction->insn->id, X86_INS_ADD)) ? true : false;
									uint32_t new_opcode = update_add_sub(is_add, imm, is_add_2, tmp_imm, &tmp_imm);
									tmp_imm = resize_immediate(tmp_imm, get_reg_at(instruction, REG_FIRST));
									//check if tmp_imm is 0
									if(tmp_imm == 0) {
										//remove the original & current instruction
										printf("[I] Zero immediate!\n");
										print_insn("[I] Delete: ", first_insn);
										print_insn("[I] Delete: ", instruction);
										ListRemove(list, first);
										free(first->content);
										ListRemove(list, next_use);
										free(next_use->content);
										//mark the list as updated
										optimized = true;
										//terminate loop
										next_use = NULL;
									} else {
										//update the instruction
										if(set_imm(instruction, tmp_imm)) {
											//set the new ID
											set_id(instruction, new_opcode);
											//reassemble the instruction
											Instruction *updated = update_insn_str(handle, instruction, mode);
											ListChangeEntry(next_use, updated);
											//remove the original instruction
											if(first) {
												ListRemove(list, first);
												free(first->content);
												free(first);
												//mark the list as updated
												optimized = true;
												//terminate loop
												next_use = NULL;
											}
										} else {
											printf("[!] Error while setting immediate, exit!\n");
											ExitProcess(EXIT_FAILURE);
										}
									}
								} else {
									//ignore this instruction
									if(VERBOSE) print_insn("[I] reg->add/sub->other: ", instruction);
								}
							} else {
								if(VERBOSE) print_insn("[I] reg->other: ", instruction);
								//found an instruction reading 'reg', terminate loop
								next_use = NULL;
							}
						} else {
							if(VERBOSE) print_insn("[I] reg->other: ", instruction);
							//found an instruction different from ADD/SUB, terminate loop
							next_use = NULL;
						}
					}
				}
			}
		}
		current = next;
	}
	return optimized;
}

/* ------------------------------------------------------------------------------------------------------------------ */