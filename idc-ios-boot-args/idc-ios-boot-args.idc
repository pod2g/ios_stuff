// idc-ios-boot-args.idc ~pod2g 2013

#include <idc.idc>

static main() {
	auto ref, i, instr, symb;
	symb = LocByName("_PE_parse_boot_argn");
	ref = RfirstB(symb);
	
	while (ref != BADADDR) {
		instr = ref;
		for (i = 0; i < 10; i = i + 1) {
			instr = PrevHead(instr, instr - 0x40); // up one instr
			if (GetMnem(instr) == "LDR" && GetOpnd(instr, 0) == "R0") {
				Message("%X boot-arg: %s\n", ref, GetString(Dword(GetOperandValue(instr, 1)), -1, 0));
				break;
			}
		}
		ref = RnextB(symb, ref);
	}
}
