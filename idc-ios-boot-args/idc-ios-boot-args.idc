// MuscleNerd, based on ida scripts from KennyTM~ and ~pod2g

#include <idc.idc>

static update(ea, reg)
{
  auto opcode, instr, val;
  val = 0;
  opcode = GetMnem(ea);
  instr = DecodeInstruction(ea);
  if (instr[0].type == o_reg && instr[0].reg == reg) {
    if (opcode == "MOVT" || opcode == "movt") {
      if (instr[1].type == o_imm && instr[1].value != 0)
	val = instr[1].value << 16;
    } else if (opcode == "MOV" || opcode == "mov" || opcode == "MOVW" || opcode == "movw") {
      if (instr[1].type == o_imm)
	val = instr[1].value;
    } else if (opcode == "LDR" || opcode == "ldr") {
      val = Dword(GetOperandValue(ea, 1));
    }
  }
  //if (val) Message("%X %s added %x\n", ea, opcode, val);
  return val;
}

static backtrack_update(reg, start, min)
{
  auto ea, pc_addr, val, cur, found, prev;
  pc_addr = start + (GetReg(start, "T") ? 4 : 8);
  val = 0;  found = 0;  prev = 0;
  for (ea = start; (ea!=BADADDR && ea>min); ea = PrevHead(ea, min)) {
    cur = update(ea, reg);
    if (cur) {
      val = val + cur;
      prev = cur;
      found = found + 1;
      if (found==2 || ((cur & 0xffff) && (cur && 0xffff0000))) {
	val = val + pc_addr;
	//Message("After %d ops, add PC to get 0x%x\n", found, val);
	return val;
      }
    }
  }
  Message("Failed to find R0 for %X\n", start);
  return 0;
}

static main() {
  auto ref, i, instr, symb, reg, val;
  symb = LocByName("_PE_parse_boot_argn");
  if (symb == BADADDR) {
    Message("Couldn't find _PE_parse_boot_argn() in this database\n");
    return;
  }
  Message("_PE_parse_boot_argn() is at %X\n", symb);
  ref = RfirstB(symb);
  while (ref != BADADDR) {
    instr = ref;
    for (i = 0; i < 20; i = i + 1) {
      instr = PrevHead(instr, instr - 0x40); // up one instr
      if ((GetMnem(instr) == "LDR" && GetOpnd(instr, 0) == "R0")) {
	Message("%X boot-arg: %s\n", ref, GetString(Dword(GetOperandValue(instr, 1)), -1, 0));
	break;
      } else if (GetMnem(instr) == "ADD" && GetOpnd(instr, 0) == "R0") {
	val = backtrack_update(0, instr, instr-100);
	Message("%X boot-arg: %s\n", ref, GetString(val, -1, 0));
	break;
      }
    }
    ref = RnextB(symb, ref);
  }
}
