from idaapi import *
from idc import *
import idautils

for seg_ea in Segments():
	name = SegName(seg_ea)
	if name.endswith("__nl_symbol_ptr"):
		
		s = get_segm_by_name(name)
		#https://www.hex-rays.com/products/decompiler/manual/tricks.shtml#02
		set_segm_class(s, "CODE")
		
		seg_end = SegEnd(seg_ea)
		i = seg_ea
		while i < seg_end:
			name = GetFunctionName(Dword(i))
			if name != "":
				print name
				for xref in list(DataRefsTo(i))[:1]:
					MakeName(xref, "_%s_stub_%x" % (name, i))
			i+=4
	
