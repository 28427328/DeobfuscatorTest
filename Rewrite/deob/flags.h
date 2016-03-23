//Display flags
#define INFO true
#define SHOW_ADDR false
#define VERBOSE true
#define VERBOSE_ERROR true
#define ENABLE_TEST_FUNCTIONS true

//Emulation testing values
#define TEXT_ADDRESS 0x401000
#define STACK_ADDRESS 0x1000
#define EMU_SIZE  2 * 1024 * 1024

//Optimizations flags
#define FIRST_PASS true
#define SECOND_PASS true

//junk elimination
#define REMOVE_FLAG_INS true
#define REMOVE_UNUSED false

//Stack expansion
#define STACK_DISPLACEMENT 0x400

/* Importing XEDParseAssemble */

typedef XEDPARSE_STATUS (WINAPI *XEDParseAssemble)(XEDPARSE *xed_parse);
XEDParseAssemble assemble;
