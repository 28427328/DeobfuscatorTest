#include <deob/tests.h>
#include <deob/list.h>
#include <deob/emulation.h>
#include <deob/optimizations.h>

//define the general list
static List *list = NULL;

#define TEST_BUILD false

int test_main() {
	//place here the test code and enable TEST_BUILD flag
	ExitProcess(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
	srand(time(NULL));
	if(TEST_BUILD) test_main();
	// Importing XEDParseAssemble from the dynamic library
	HANDLE XEDLib = LoadLibrary("XEDParse.dll");
	if(XEDLib == NULL) {
		printf("[-] Error: LoadLibrary - 0x%x\n", GetLastError());
		return EXIT_FAILURE;
	}
	assemble = (XEDParseAssemble)GetProcAddress(XEDLib, "XEDParseAssemble");
	if(assemble == NULL) {
		printf("[-] Error: GetProcAddress - 0x%x\n", GetLastError());
		return EXIT_FAILURE;
	}
	// Optimizing for stack operations
	csh handle;
	cs_insn *insn;
	cs_err err;
	size_t count;
	err = cs_open(CS_ARCH_X86, MODE, &handle);
	if(err != CS_ERR_OK) {
		printf("[-] Error: cs_open.\n");
		return -1;
	}
	//I want all possible details
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if(count > 0) {
		//create list
		list = ListCreate();
		//adding original instructions to list
		Instruction *current = NULL;
		ListEntry *entry = NULL;
		for(size_t i = 0; i < count; i++) {
			current = calloc(1, sizeof(Instruction));
			current->insn = (cs_insn *)calloc(1, sizeof(cs_insn));
			memcpy(current->insn, &insn[i], sizeof(cs_insn));
			entry = ListEntryCreate(current);
			ListPush(list, entry);
		}
		printf("[!] Original code\n\n");
		print_disassembly(handle, list, INFO);
		//init a fake initial registers context that will be used across the execution
		Registers *start_regs;
		init_reg_context(&start_regs, STACK_ADDRESS, MODE);
		//emulate the obfuscated code and save the end registers context result
		Registers *end_regs = calloc(1, sizeof(Registers));
		List *mem_writes = ListCreate();
		emulate_context(handle, list, start_regs, end_regs, mem_writes, MODE);
		if(!ListIsEmpty(mem_writes)) printf("The following memory locations are WRITE\n");
		print_memory_value(mem_writes);
		//start main optimization loop
		bool optimized;
		//first pass
		if(FIRST_PASS) {
			do {
				optimized = false;
				while(expand_stack_ins(handle, list, MODE)) { optimized = true; }
				while(collapse_add_sub(handle, list, MODE)) { optimized = true; }
				while(emulate_stack_reg(handle, list, start_regs, MODE)) { optimized = true; }
			} while(optimized);
		}
		//show code after main optimization loop
		if(VERBOSE) {
			printf("\n\n------------ Temporary code 1 ------------\n\n");
			print_disassembly(handle, list, INFO);
			//emulate new context
			Registers *end_regs_new = calloc(1, sizeof(Registers));
			List *mem_writes_new = ListCreate();
			emulate_context(handle, list, start_regs, end_regs_new, mem_writes_new, MODE);
			if(check_context_integrity(end_regs, mem_writes, end_regs_new, mem_writes_new)) {
				printf("\n[OK] Integrity kept! :D\n");
			} else {
				printf("\n[NO] Integrity destroyed! D:\n");
			}
		}
		//free memory
		ListDestroy(mem_writes);
		free(end_regs);
		free(start_regs);
		cs_free(insn, count);
	} else {
		printf("[-] Error: cs_disasm.\n");
	}
	cs_close(&handle);
	return 0;
}
