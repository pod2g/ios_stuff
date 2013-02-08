// ios-llvm.idc ~pod2g 2012

#include <idc.idc>

static main() {
	auto lastAddr, oldAddr, minAddr, maxAddr;
	minAddr = 0;
	maxAddr = -1;
	
	lastAddr = minAddr;
	do {
		auto addAddr, moveAddr, pMove, pMovt, movtAddr, idx, relAddr, disasmAdd, ridx, comment, absAddr;
		
		lastAddr = FindText(lastAddr, SEARCH_DOWN|SEARCH_REGEX, 0, 0, "ADD.*R.*PC");
		if (lastAddr == BADADDR || lastAddr == oldAddr) break; // 2 loops with the same result then bye.
		oldAddr = lastAddr;
		
		addAddr = lastAddr;
		lastAddr = lastAddr + 2; // if we encounter a continue, lastAddr is already incremented.
		if (maxAddr != -1 && lastAddr > maxAddr) break;
		
		disasmAdd = GetDisasm(addAddr);
		idx = strstr(disasmAdd, "R");
		if (idx == -1) continue;
	
		ridx = substr(disasmAdd, idx + 1, idx + 2);
		pMove = "MOV[^T].*R" + ridx + ".*0x.*";
		moveAddr = FindText(addAddr, SEARCH_REGEX, 0, 0, pMove);
		if (moveAddr == BADADDR || addAddr - moveAddr > 0x20) continue;
		
		pMovt = "MOVT.*R" + ridx + ".*#.*";
		movtAddr = FindText(addAddr, SEARCH_REGEX, 0, 0, pMovt);

		relAddr = GetOperandValue(moveAddr, 1);
		if (movtAddr != BADADDR && movtAddr > moveAddr) {
			relAddr = relAddr + (GetOperandValue(movtAddr, 1) << 16);
		}
		
		absAddr = addAddr + relAddr + 4;
		comment = NameEx(BADADDR, absAddr);
		if (comment == "") {
			comment = "0x" + ltoa(absAddr, 16);
		}
		MakeComm(addAddr, comment);
		AddCodeXref(addAddr, absAddr, XREF_USER);
		Jump(addAddr);
	} while (lastAddr != BADADDR);
}
