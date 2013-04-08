from idaapi import *
from idc import *
import idautils


def old_do_pointers():
	for seg_ea in Segments():
		name = SegName(seg_ea)
		if not name.endswith("__const"):
			continue
		print name
		seg_end = SegEnd(seg_ea)
		print name,seg_end
		i = seg_ea
		while i < seg_end:
			dw = Dword(i)
			if dw & 0x80000000 == 0x80000000:
				if SegName(dw):
					OpOffset(i, 0)
			i += 4

#good enough for ios6 kernel
def backtrack(ea, reg):
	track = reg
	while ea!=BADADDR:
		if GetDisasm(ea).startswith("PUSH"):
			break
		mnem = idc.GetMnem(ea)
		op0 = idc.GetOperandValue(ea,0)
		op1 = idc.GetOperandValue(ea,1)
		if op0 == track:
			xrefs = list(DataRefsFrom(ea))
			if len(xrefs):
				return xrefs[0]
			if idc.GetOpType(ea,1) == o_reg: #1=register
				track= op1
			else:
				return op1
		ea=PrevHead(ea)
	return None
	
def find_args(ea):
	r0 = backtrack(ea, 0)
	r1 = backtrack(ea, 1)
	r2 = backtrack(ea, 2)
	r3 = backtrack(ea, 3)

	if not None in [r0, r1, r2, r3]:
		name = GetString(r1)
		parent_meta = r2
		if r2 != 0 and SegName(r2).endswith("__nl_symbol_ptr"):
			#print "deref for class %s" % name
			parent_meta = Dword(r2)
		current_meta = r0
		if r0 != 0 and SegName(r0).endswith("__nl_symbol_ptr"):
			#print "xxderef for class %s" % name
			current_meta = Dword(r0)
		return name, parent_meta, r3, current_meta
	return None, None, None, None

class IOKitInspector(object):
	def __init__(self):
		self.classes = {}
		
	def find_class_by_name(self, name):
		for c in self.classes.values():
			if c["name"] == name:
				return c

	def print_inheritance(self, name):
		print " => ".join(self.get_parents(name))

	def is_userclient(self, name):
		return "IOUserClient" in self.get_parents(name)

	def get_parents(self, name):
		parents = []
		c = self.find_class_by_name(name)
		while c:
			parents.append(c["name"])
			c = self.classes.get(c["parentMeta"])
		return parents

	def doStuff(self, xref):
		name, parent, sz, current = find_args(xref)

		if not name or current == 0x0 or parent == -1:
			return
		if self.classes.has_key(current):
			print "duplicate %s" % name
			return
		c = {"name": name, "meta": current, "parentMeta": parent, "size": sz}
		#print c
		self.classes[current] = c

	def find_vtable(self, name):
		c = self.find_class_by_name(name)
		for xref in DataRefsTo(c["meta"]):
			disas = GetDisasm(xref)
			if not disas.split()[1].replace(",","") == "R0":
				continue
			next= GetDisasm(NextHead(xref))
			if next.startswith("BX              LR"):
				refs = list(DataRefsTo(xref-2))#hax ios 6thumb
				#print refs, "%x" % xref
				if len(refs) != 1:
					return
				vtable = refs[0] - 7*4
				print "%s_getMetaClass %x" % (name, xref-2)
				print "%s vtable %x" % (name, vtable)
				return vtable
				
	def searchClasses(self):
		self.classes = {}

		OSMetaClassConstructor = LocByName("__ZN11OSMetaClassC2EPKcPKS_j")

		for xref in CodeRefsTo(OSMetaClassConstructor, 0):
			self.doStuff(xref)
		
		for dxref in DataRefsTo(OSMetaClassConstructor):
			for stub_xref in DataRefsTo(dxref):
				f = GetFunctionName(stub_xref)
				#-10=hax based on stub instruction size
				for xref in CodeRefsTo(stub_xref-10, 0):
					self.doStuff(xref)

		print "%d classes found" % len(self.classes)
		return
		for c in self.classes.values():
			self.print_inheritance(c["name"])
			self.fix_vtable(c["name"])
			#vtable = find_vtable(meta)
			#print name,  "%x" % xref, "%x" % meta#, "%x" % vtable
			#fix_vtable(name, meta)

	def fix_vtable(self, classname):
		parents = self.get_parents(classname)
		last_vtable = None
		last_class = None
		names = {}
		for cn in reversed(parents):
			print cn
			vtable = self.find_vtable(cn)
			if not vtable:
				print "Vtable fail %s" % cn
				continue
			print "%x" % vtable
			vt = get_null_terminated_array(vtable)
			if last_vtable and len(last_vtable) > len(vt):
				print "wut %d %d" % (len(last_vtable) , len(vt))
			for i in xrange(len(vt)):
				fname = GetFunctionName(vt[i])
				if not fname.startswith("sub_"):
					continue
				if last_vtable and i < len(last_vtable):
					if last_vtable[i] != vt[i]:
						parent_fname = GetFunctionName(last_vtable[i])
						demangled = Demangle(parent_fname, GetLongPrm(INF_LONG_DN))
						if demangled:
							proto = demangled_to_proto(demangled, cn)
							print fname, " => ", proto
							print SetType(vt[i] & ~1, proto)
							newname = proto.split("(")[0].split()[1]
							names[newname] = names.get(newname, -1) + 1
							newname += "_" * names[newname]
							MakeName(vt[i] & ~1, newname)
						else:
							print parent_fname, fname
			last_vtable = vt
			last_class = cn

	def make_vtable_struct(self, c):
		vtable = self.find_vtable(c["name"])
		vt = get_null_terminated_array(vtable)
		x = []
		names = {}
		for fptr in vt:
			fname = get_function_name(fptr)
			zz = fname.split(")(")[0]
			names[zz] = names.get(zz, -1) + 1
			z = zz + "_" * names[zz]
			fname = fname.replace(zz, z)
			x.append(("uint32_t", fname))
		s = print_struct("%s_vtable" % c["name"], x)
		print s
		idc.ParseTypes(s, 0)
		
	def make_structs(self, classname):
		parents = self.get_parents(classname)
		parent_size = 4
		parent_name = None
		for cn in reversed(parents):
			c = self.find_class_by_name(cn)
			s1 = "_%s" % cn
			s2 = "%s" % cn
			sz = c["size"] - parent_size
			m1 = [("uint32_t", "var%d" % i) for i in xrange(sz/4)]
			if parent_name:
				m1 = [("_%s" % parent_name, parent_name.lower())] + m1

			ss1 = print_struct(s1, m1)
			idc.ParseTypes(ss1, 0)
			print ss1
			m2 = [("%s_vtable*" % cn, "vtable")]
			m2.append((s1, "m"))
			print "//sizeof=%d" % c["size"]
			ss2 = print_struct(s2, m2)
			idc.ParseTypes(ss2, 0)
			print ss2
			parent_size = c["size"]
			parent_name = cn
		
	def make_forward(self):
		stuff = ["OSMetaClassBase",
				"IOPMPowerState",
				"semaphore",
				"ipc_port",
				"task",
				"upl_page_info",
				"IOInterruptVector"]
		txt = "\n".join(map(lambda x:"struct %s;"%x, stuff))
		for c in self.classes.values():
			txt += "struct %s;\n" % c["name"]
		idc.ParseTypes(txt, 0)
		print txt

	def do_class(self, name):
		c = self.find_class_by_name(name)
		self.make_vtable_struct(c)
		self.make_structs(c["name"])
		self.fix_vtable(c["name"])
		
def sanitize_function_name(x):
	return x.replace("const", "").replace("~", "destructor_")
	
def get_function_name(ea):
	fname = GetFunctionName(ea)
	demangled = Demangle(fname, GetLongPrm(INF_LONG_DN))
	if demangled:
		x = demangled.split("::")[1]
		z = "(*%s)(%s" % (x.split("(",1)[0], x.split("(",1)[1])
		return sanitize_function_name(z)
	return fname
	
def demangled_to_proto(demangled, classname):
	p = demangled.split("::")[1]
	method, params = p.split("(", 1)
	p = "%s*" % classname
	if params.split(")")[0].strip() != "":
		p += ", %s" % params
	else:
		p += ")"
	res = "uint32_t %s__%s(%s;" % (classname, method, p)
	return sanitize_function_name(res)
	
def print_struct(name, members):
	txt = "typedef struct %s{\n" % name
	for t,n in members:
		txt += "\t%s %s;\n" % (t,n)
	txt += "} %s;\n\n" % name
	return txt
		
def get_null_terminated_array(ea):
	r = []
	while True:
		x = Dword(ea)
		if x == 0:
			break
		r.append(x)
		ea += 4
	return r

def func_name_to_label(f):
	z = f.split("::")
	return "%s_%s" % (z[0], z[1].split("(")[0])

iok = IOKitInspector()
iok.searchClasses()

#iok.print_inheritance("AppleIOPFMI")
#iok.print_inheritance("IOFlashControllerUserClient")
#iok.print_inheritance("AppleMultitouchSPIUserClient")
#iok.make_forward()
