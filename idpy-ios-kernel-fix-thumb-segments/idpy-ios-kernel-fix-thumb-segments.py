# idpy-ios-kernel-fix-thumb-segments.py ~pod2g 2013

from idaapi import *
from idc import *

for seg in Segments():
	start = seg
	if Word(start) & 0xff00 == 0xb500 and GetReg(seg, "T") == 0:
                print "Switching from ARM to THUMB for segment: 0x%X" % seg;
		MakeUnkn(start, 1);
		for i in range (seg, seg + 0x40):
			SetReg(i, "T", 1);
		MakeCode(start);

