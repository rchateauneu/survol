import r2pipe

# Temporary.
import os
os.environ["PATH"] = os.environ["PATH"] + ";C:\\Users\\rchateau\\AppData\\Local\\Programs\\radare2"

def SimpleTest():
	namExe = "C:\\Windows\\System32\\notepad.exe"
	namDll = "C:\\Windows\\System32\\normaliz.dll"

	r = r2pipe.open(namDll)

	# pd 10: Disassemble 10 instructions.
	# ii: Imports
	# iI: Informations generales.
	# ie: Entry points.
	# iz: Strings from code section.
	# izz: Strigns from entire binary; https://blog.dutchcoders.io/getting-started-with-radare2/
	# iz~http : Strings matching http. Does not work with regex.
	# iE: Exports.
	# afl: List on functions.
	# agC : Call graph ??
	#
	# r2graphity:
	#
	# "Returns a dictionary of xrefs to symbols"
	# axt @@ sym.*
	# "axtj @ " + hex(stringItem['vaddr'])
	#
	# "Returns an executables imports as a list"
	# ii
	#
	# izzj parses entire binary
	# izzj
	#
	#
	# "?v $FB @ " + stringAddr
	#
	# Creating the NetworkX graph, nodes are functions, edges are calls or callbacks
	# aflj
	#
	# General format of radare2 commands:
	# [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...
	#
	cmds = ["pd 10","iI","ie","iS","iz","afl"]
	for cm in cmds:
		print("Command=",cm)
		print(r.cmd(cm))

	print(r.cmdj("aoj")[0]['size'])
	r.quit()

	# https://github.com/radare/radare2/blob/master/doc/intro.md

	# https://recon.cx/2017/montreal/resources/slides/RECON-MTL-2017-Bubble_Struggle.pdf
	# Fruchterman-Rheingold

	# rafind2: find byte patterns into files

def TestEarth():
	filNam = r"C:\Program Files (x86)\Google\Google Earth Pro\client\googleearth.exe"
	# radare2 -2 -q -c "aaa;axt @@ sym.*" "C:\Program Files (x86)\Google\Google Earth Pro\client\googleearth.exe" > toto.tmp

	r = r2pipe.open(filNam)

	toto = r.cmd("aaa")
	print("AAA ok")
	toto = r.cmd("axtj @@ sym.*")
	print(toto)

#sub.KERNEL32.dll_GetVersionExW_f50 0x483f93 [CALL] call dword sym.imp.KERNEL32.dll_GetVersionExW
#sub.KERNEL32.dll_GetVersionExW_f50 0x483fdb [CALL] call dword sym.imp.KERNEL32.dll_GetVersionExW

# On dirait que les destinatiosn sont regroupees.
# Pas du tout le meme layout que "axt @@ sym.*"
#	[
#		{"from":4246961,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4246928,"fcn_name":"sub.MSVCR120.dll_malloc_d90"},
#		{"from":4247009,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4246976,"fcn_name":"sub.MSVCR120.dll_malloc_dc0","flag":"sub.MSVCR120.dll_malloc_d90"},
#		{"from":4498679,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4498672,"fcn_name":"sub.MSVCR120.dll_malloc_4f0"},
#		{"from":4862036,"type":"DATA","opcode":"mov edx, dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4861920,"fcn_name":"sub.MSVCR120.dll_malloc_fe0"},
#		{"from":4968987,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4968256,"fcn_name":"sub.unzip_1.01_Copyright_1998_2004_Gilles_Vollant___http:__www.winimage.com_zLibDll_f40"},
#		{"from":4969799,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc"},{"from":4971493,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4971360,"fcn_name":"sub.MSVCR120.dll_malloc_b60"},
#		{"from":4971526,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4971360,"fcn_name":"sub.MSVCR120.dll_malloc_b60"},
#		{"from":4980452,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc","fcn_addr":4979440,"fcn_name":"sub.MSVCR120.dll_malloc_af0"},
#		{"from":4981152,"type":"CALL","opcode":"call dword sym.imp.MSVCR120.dll_malloc"},
#	]







TestEarth()