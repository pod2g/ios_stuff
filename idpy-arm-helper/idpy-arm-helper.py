# IDA Helper for ARM / iOS binary files
#  - from Analyse.py (https://www.assembla.com/code/ks360/subversion/nodes/utils/Analyze.py)
#
# (c) pod2g 02/2013

from idaapi import *
from idc import *

# Iterate over all segments
for i in Segments():
	start = i
	end = GetSegmentAttr(start, SEGATTR_END)

	# Discover exception vectors (boot loaders)
	if Dword(start) == 0xea00000e :
		for i in range (start, start + 0x20, 4):
			SetReg(i, "T", 0);
			MakeCode(i);

	# Search for ARM PUSH
	addr = start
	while (addr != BADADDR):
		addr = FindBinary  (addr, SEARCH_DOWN, '2D E9', 16)
		if(addr != BADADDR ):
			addr = addr - 2
			if (addr % 4) == 0 and getFlags(addr) < 0x200 :
				# addr is DWORD aligned, 2nd word is 2D E9 and unexplored
                                print "ARM: 0x%X" % addr;
				for i in range (addr, addr + 0x8):
					SetReg(i, "T", 0);
                                MakeFunction(addr);
			addr = addr + 4
	# Search for THUMB PUSH
	addr = start
	while (addr != BADADDR):
		addr = FindBinary  (addr, SEARCH_DOWN, 'B5', 16)
		if(addr != BADADDR ):
			addr = addr - 1
			if (addr % 4) == 0 and getFlags(addr) < 0x200 :
				# addr is DWORD aligned, 2nd byte is B5 and unexplored
                                print "TMB: 0x%X" % addr;
				for i in range (addr, addr + 0x8):
					SetReg(i, "T", 1);
                                MakeFunction(addr);
	
			addr = addr + 2


# Force IDA analysis
for i in Segments():
        start = i
        end = GetSegmentAttr(start, SEGATTR_END)
        AnalyzeArea(start, end)
