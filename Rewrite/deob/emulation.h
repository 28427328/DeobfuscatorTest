uint64_t random_reg_value() {
	uint64_t num = rand();
	num = (num << 32 | rand());
	num = (num % (999999999 - 100000000)) + 100000000;
	return num;
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
	//printf("old addr: 0x%llx\n", addr);
	switch(MODE) {
		case CS_MODE_32:
			addr &= 0xFFFFF000;
			break;
		case CS_MODE_64:
			addr &= 0xFFFFFFFFFFFFF000;
			break;
	}
	//printf("new addr: 0x%llx\n", addr);
	uc_err err;
    switch(type) {
        default:
            //printf("UC_HOOK_MEM_INVALID type: %d at 0x%" PRIx64 "\n", type, addr);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_READ_UNMAPPED:
            //printf("UC_MEM_READ_UNMAPPED at 0x%"PRIx64 ", data size = %u\n", addr, size);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_WRITE_UNMAPPED:
            //printf("UC_MEM_WRITE_UNMAPPED at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_FETCH_PROT:
            //printf("UC_MEM_FETCH_PROT at 0x%"PRIx64 "\n", addr);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_WRITE_PROT:
            //printf("UC_MEM_WRITE_PROT at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
        case UC_MEM_READ_PROT:
            //printf("UC_MEM_READ_PROT at 0x%"PRIx64 ", data size = %u\n", addr, size);
            // map this memory in with 2MB in size
            err = uc_mem_map(uc, addr, 2 * 1024*1024, UC_PROT_ALL);
            // return true to indicate we want to continue
            return true;
    }
}

static bool hook_mem_access(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
	List *mem_list = (List *)user_data;
	switch(type) {
        default: break;
        case UC_MEM_READ:
                //printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n", addr, size);
                break;
        case UC_MEM_WRITE:
        		if(!(addr >= STACK_ADDRESS && addr <= (STACK_ADDRESS + EMU_SIZE))) {
                	//if(VERBOSE) printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
        			if(mem_list) {
	        			MemoryValue *mem_val = calloc(1, sizeof(MemoryValue));
	        			mem_val->address = addr;
	        			mem_val->size = size;
	        			mem_val->value = value;
	        			ListEntry *new_entry = ListEntryCreate(mem_val);
	        			ListPush(mem_list, new_entry);
	        		}
        		}
                break;
    }
}

static void hook_code(uc_engine *uc, uint64_t address, int32_t size, void *user_data) {
	//this function could be used to trace & modify operation while emulating code
	/*printf("EIP/RIP: 0x%llx, SIZE: 0x%llx\n", address, size);
	uint32_t rsp;
	uc_reg_read(uc, UC_X86_REG_ESP, &rsp);
	printf("[!] rsp: 0x%x\n", rsp);
	uint8_t bytes[0xFF];
	uc_mem_read(uc, address, bytes, size);
	printf("[!] bytes: ");
	for(size_t i = 0; i < size; i++) {
		printf("%02x ", bytes[i]);
	}
	printf("\n");*/
}

/*
	Name: print_reg_context
	Description: outputs the register context passed as argument
*/
void print_reg_context(csh handle, Registers *regs, uint8_t mode) {
	printf("\n[!] Register Context\n");
	uint8_t reg_name[0x10] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBP, X86_REG_RSP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15
	};
	uint32_t count = (mode == CS_MODE_32) ? 8 : 16;
	for(size_t i = 0; i < count; i++) {
		printf("%s = 0x%llx\n", cs_reg_name(handle, reg_name[i]), ((uint64_t **)regs)[i]);
	}
}

/*
	Name: init_regs_context
	Description: this function initializes a registry context given a pointer to the structure
	and a mode (CS_MODE_32 or CS_MODE_64). The stack address is used to initialize the ESP/RSP
	value; the other registers are initialized at random values.
*/
void init_reg_context(Registers **regs, uint64_t stack_address, uint8_t mode) {
	//remember to free the allocation as soon as you don't need it anymore
	*regs = (Registers *)calloc(1, sizeof(Registers));
	//every register is initialized with a random value
	(*regs)->rax = random_reg_value();
	(*regs)->rbx = random_reg_value();
	(*regs)->rcx = random_reg_value();
	(*regs)->rdx = random_reg_value();
	(*regs)->rbp = random_reg_value();
	(*regs)->rsp = stack_address + (stack_address / 2);
	(*regs)->rsi = random_reg_value();
	(*regs)->rdi = random_reg_value();
	//if the mode is CS_MODE_64 also r8-r15 are initialized
	if(mode == CS_MODE_64) {
		(*regs)->r8 = random_reg_value();
		(*regs)->r9 = random_reg_value();
		(*regs)->r10 = random_reg_value();
		(*regs)->r11 = random_reg_value();
		(*regs)->r12 = random_reg_value();
		(*regs)->r13 = random_reg_value();
		(*regs)->r14 = random_reg_value();
		(*regs)->r15 = random_reg_value();
	}
}

/*
	Name: copy_reg_context
	Description: this function copies the registers context from 'old_c' to 'new_c'.
*/
bool copy_reg_context(Registers *old_c, Registers *new_c) {
	if(!old_c) return true;
	if(!new_c) return false;
	//the full x64 context is copied here, also if uninitialized
	memcpy(new_c, old_c, sizeof(Registers));
	return true;
}

/*
	Name: emulate_code
	Description: this function emulates assembly instructions starting from 'start' to 'end'.
	A register context is passed to the function to be used as starting point and updated
	with new values at the emulation end. Also a MemoryLocation list can be passed, and it will
	be updated with address-value of each WRITE.
*/
void emulate_code(csh handle, ListEntry *start, ListEntry *end, Registers *regs, List *mem, uint8_t mode) {
	if(!regs) return;
	//generate the byte array to be emulated
	uint64_t assembly_size = 0;
	if(!start) return;
	ListEntry *current = start;
	Instruction *instruction;
	while(current && current != end) {
		instruction = (Instruction *)current->content;
		assembly_size += instruction->insn->size;
		current = current->next;
	}
	uint8_t *assembly = calloc(assembly_size, sizeof(uint8_t));
	current = start;
	uint64_t index = 0;
	while(current && current != end) {
		instruction = (Instruction *)current->content;
		memcpy((assembly + index), instruction->insn->bytes, instruction->insn->size);
		index += instruction->insn->size;
		current = current->next;
	}
	//setup emulation environment
	uc_engine *uc;
	uc_err err;
	err = uc_open(UC_ARCH_X86, mode, &uc);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_open, %s\n", uc_strerror(err));
		return;
	}
	//mapping .text memory, but one should actually allocate every useful piece of memory
	err = uc_mem_map(uc, TEXT_ADDRESS, EMU_SIZE, UC_PROT_ALL);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_map, %s\n", uc_strerror(err));
		return;
	}
	//mapping .stack memory (at a standard address, is not really important to be specific)
	err = uc_mem_map(uc, STACK_ADDRESS, EMU_SIZE, UC_PROT_ALL);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_map, %s\n", uc_strerror(err));
		return;
	}
	/*if(VERBOSE) {
		printf("[I] Machine code to be emulated:\n");
		for(size_t i = 0; i < assembly_size; i++) {
			printf("%x ", assembly[i]);
		}
	}*/
	//writing machine code to .text memory
	err = uc_mem_write(uc, TEXT_ADDRESS, assembly, assembly_size);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_mem_write, %s\n", uc_strerror(err));
		return;
	}
	//adding hook to trace-step instructions
	uc_hook hook_id = 0, hook_id_2 = 0, hook_id_3 = 0;
	//trace every instruction
	uc_hook_add(uc, &hook_id, UC_HOOK_CODE, hook_code, NULL, TEXT_ADDRESS, TEXT_ADDRESS + assembly_size);
	//intercept invalid memory events
    uc_hook_add(uc, &hook_id_2, UC_HOOK_MEM_INVALID, hook_mem_invalid, NULL, (uint64_t)1, (uint64_t)0);
    //intercept memory access
    uc_hook_add(uc, &hook_id_3, UC_HOOK_MEM_WRITE|UC_HOOK_MEM_READ, hook_mem_access, mem, (uint64_t)1, (uint64_t)0);
	//write registers to emulation context
	switch(mode) {
		case CS_MODE_32:
			uc_reg_write(uc, UC_X86_REG_EAX, &(regs->rax));
			uc_reg_write(uc, UC_X86_REG_EBX, &(regs->rbx));
			uc_reg_write(uc, UC_X86_REG_ECX, &(regs->rcx));
			uc_reg_write(uc, UC_X86_REG_EDX, &(regs->rdx));
			uc_reg_write(uc, UC_X86_REG_ESP, &(regs->rsp));
			uc_reg_write(uc, UC_X86_REG_EBP, &(regs->rbp));
			uc_reg_write(uc, UC_X86_REG_ESI, &(regs->rsi));
			uc_reg_write(uc, UC_X86_REG_EDI, &(regs->rdi));
			break;
		case CS_MODE_64:
			uc_reg_write(uc, UC_X86_REG_RAX, &(regs->rax));
			uc_reg_write(uc, UC_X86_REG_RBX, &(regs->rbx));
			uc_reg_write(uc, UC_X86_REG_RCX, &(regs->rcx));
			uc_reg_write(uc, UC_X86_REG_RDX, &(regs->rdx));
			uc_reg_write(uc, UC_X86_REG_RSP, &(regs->rsp));
			uc_reg_write(uc, UC_X86_REG_RBP, &(regs->rbp));
			uc_reg_write(uc, UC_X86_REG_RSI, &(regs->rsi));
			uc_reg_write(uc, UC_X86_REG_RDI, &(regs->rdi));
			uc_reg_write(uc, UC_X86_REG_R8, &(regs->r8));
			uc_reg_write(uc, UC_X86_REG_R9, &(regs->r9));
			uc_reg_write(uc, UC_X86_REG_R10, &(regs->r10));
			uc_reg_write(uc, UC_X86_REG_R11, &(regs->r11));
			uc_reg_write(uc, UC_X86_REG_R12, &(regs->r12));
			uc_reg_write(uc, UC_X86_REG_R13, &(regs->r13));
			uc_reg_write(uc, UC_X86_REG_R14, &(regs->r14));
			uc_reg_write(uc, UC_X86_REG_R15, &(regs->r15));
			break;
	}
	//emulate code
	uint64_t esp = 0;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);
	err = uc_emu_start(uc, TEXT_ADDRESS, TEXT_ADDRESS + assembly_size, 0, 0);
	if(err != UC_ERR_OK) {
		printf("[-] Error: uc_emu_start, %s\n", uc_strerror(err));
		return;
	}
	//delete hook
	uc_hook_del(uc, hook_id);
	uc_hook_del(uc, hook_id_2);
	uc_hook_del(uc, hook_id_3);
	//read registers from emulation context
	switch(mode) {
		case CS_MODE_32:
			uc_reg_read(uc, UC_X86_REG_EAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_EBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_ECX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_EDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_ESP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_EBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_ESI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_EDI, &(regs->rdi));
			break;
		case CS_MODE_64:
			
			uc_reg_read(uc, UC_X86_REG_RAX, &(regs->rax));
			uc_reg_read(uc, UC_X86_REG_RBX, &(regs->rbx));
			uc_reg_read(uc, UC_X86_REG_RCX, &(regs->rcx));
			uc_reg_read(uc, UC_X86_REG_RDX, &(regs->rdx));
			uc_reg_read(uc, UC_X86_REG_RSP, &(regs->rsp));
			uc_reg_read(uc, UC_X86_REG_RBP, &(regs->rbp));
			uc_reg_read(uc, UC_X86_REG_RSI, &(regs->rsi));
			uc_reg_read(uc, UC_X86_REG_RDI, &(regs->rdi));
			uc_reg_read(uc, UC_X86_REG_R8, &(regs->r8));
			uc_reg_read(uc, UC_X86_REG_R9, &(regs->r9));
			uc_reg_read(uc, UC_X86_REG_R10, &(regs->r10));
			uc_reg_read(uc, UC_X86_REG_R11, &(regs->r11));
			uc_reg_read(uc, UC_X86_REG_R12, &(regs->r12));
			uc_reg_read(uc, UC_X86_REG_R13, &(regs->r13));
			uc_reg_read(uc, UC_X86_REG_R14, &(regs->r14));
			uc_reg_read(uc, UC_X86_REG_R15, &(regs->r15));
			break;
	}
	//freeing assembly
	free(assembly);
}

/*
	Name: emulate_context
	Description: this function emulates the registry and memory context after the execution of the code
	contained in the List passed as argument. If mod_reg & mem are NULL the context is only displayed
	if the VERBOSE flag is set, and not saved.
*/
void emulate_context(csh handle, List *list, Registers *regs, Registers *mod_regs, List *mem, uint8_t mode) {
	//find which registers are changing
	Registers *old_regs = calloc(1, sizeof(Registers));
	//copying old registers to be able to check after emulation
	copy_reg_context(regs, old_regs);
	//emulate code from first to last instruction
	emulate_code(handle, list->first, list->last->next, regs, mem, mode);
	//check which register is changed and save the instructions modifying it
	uint8_t reg_name[16] = {
		X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBP, X86_REG_RSP, X86_REG_RSI, X86_REG_RDI,
		X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15
	};
	if(VERBOSE) printf("\n[!] The following registers are changed\n");
	uint64_t old_reg, new_reg;
	for(size_t i = 0; i < 16; i++) {
		old_reg = (uint64_t)((uint64_t **)old_regs)[i];
		new_reg = (uint64_t)((uint64_t **)regs)[i];
		if(mod_regs) ((uint64_t *)mod_regs)[i] = new_reg;
		if(old_reg != new_reg) {
			if(VERBOSE) printf("%s [OLD = 0x%llx][NEW = 0x%llx]\n", cs_reg_name(handle, reg_name[i]), old_reg, new_reg);
		}
	}
	//reset original regs
	copy_reg_context(old_regs, regs);
	//freeing space
	free(old_regs);
}

/*
	Name: check_context_integrity
	Description: this function does a simple context integrity check, but it does not check the semantic
	of the executed code. Given a knowm and unknown register & memory context, the two are
	compared and if something different is found the result is FALSE.
*/
bool check_context_integrity(Registers *old_regs, List *old_mem, Registers *new_regs, List *new_mem) {
	bool integrity_kept = true;
	//check first the register context
	if(old_regs && new_regs)
		integrity_kept = (memcmp(old_regs, new_regs, sizeof(Registers)) == 0) ? true : false;
	if(old_mem && new_mem && old_mem->entry_count > 0) {
			ListEntry *current = old_mem->first;
			while(integrity_kept && old_mem->entry_count > 0) {
				integrity_kept = ListCmpEntries(ListPop(old_mem), ListPop(new_mem), sizeof(MemoryValue));
			}
	}
	return integrity_kept;
}
