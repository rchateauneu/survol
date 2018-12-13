# https://github.com/angr/angr-doc/pull/122/commits/c478f26f12411f567669530385d146194ef58031
# We are using angr's CFGAccurate to generate a CFG from the given binary which asks for a specific user input.
# As angr itself cannot display CFGs (e.g. as png-files), we are using [angrutils'](https://github.com/axt/angr-utils) function plot_cfg.
# The various parameters of CFGAccurate are described in the [docs](docs/analyses/cfg_accurate.md)
# and in the [api](http://angr.io/api-doc/angr.html#angr.analyses.cfg_accurate.CFGAccurate).


import angr
#from angrutils import plot_cfg

# CFG very slow with this.
# https://docs.angr.io/built-in-analyses/cfg
# The CFG analysis does not distinguish between code from different binary objects.
# This means that by default, it will try to analyze control flow through loaded shared libraries.
# This is almost never intended behavior, since this will extend the analysis time to several days, probably.
proj = angr.Project("C:\\Windows\\System32\\notepad.exe", load_options={'auto_load_libs': False})
#proj = angr.Project("C:\\Windows\\System32\\normaliz.dll", load_options={'auto_load_libs': False})

print(proj.loader)
print(proj.loader.main_object)
print("main_object",dir(proj.loader.main_object))
print("")
print("Arch=",proj.arch)
print("Entry=",proj.entry)
print("Filename=",proj.filename)

# exit(0)


cfg_fast = proj.analyses.CFGFast()
print("cfg_fast:",dir(cfg_fast))


print("")
print("functions:",dir(cfg_fast.functions))
print("")
print("callgraph:",dir(cfg_fast.functions.callgraph))
print("")
print("callgraph:",cfg_fast.functions.callgraph.name)
print("")
print("callgraph: number_of_edges:",cfg_fast.functions.callgraph.number_of_edges())
print("")
print("callgraph: number_of_edges:",len(cfg_fast.functions.callgraph.edges()))
print("")
print("callgraph: number_of_nodes:",cfg_fast.functions.callgraph.number_of_nodes())
print("")
print("callgraph: number_of_nodes:",len(cfg_fast.functions.callgraph.nodes()))
print("")

print("callgraph: Loop on edges")
for ed in cfg_fast.functions.callgraph.edges():
	print(ed)
	print(dir(ed))
	print(str(ed))
	break
print("")

print("callgraph: Loop on nodes")
for nd in cfg_fast.functions.callgraph.nodes():
	print(nd)
	print(dir(nd))
	print(str(nd))
	break
print("")

print("This is the graph:", cfg_fast.graph)
print("It has %d nodes and %d edges" % (len(cfg_fast.graph.nodes()), len(cfg_fast.graph.edges())))

print("number of functions:",len(cfg_fast.functions.keys()))
print("")


#print("keys:",cfg_fast.functions.keys())
#print("")
i = 0

# https://docs.angr.io/built-in-analyses/cfg
for fff in cfg_fast.functions:
	print(fff)
	theFunc = cfg_fast.functions[fff]
	print(theFunc)
	print(theFunc.string_references())
	print(theFunc.name)

	for callsite_addr in theFunc.get_call_sites():
		callTo = theFunc.get_call_target(callsite_addr)
		callFrom = theFunc.get_call_return(callsite_addr)
		print("    To/From:",callTo,callFrom)
		try:
			funcTo = cfg_fast.functions[callTo]
		except KeyError:
			funcTo = "NoFuncTo"
		try:
			funcFrom = cfg_fast.functions[callFrom]
		except KeyError:
			funcFrom = "NoFuncFrom"
		print("    To/From:",funcTo,funcFrom)

	i += 1
	if i > 3:
		break

# Ca marche avec un exe mais pas avec une dll, apparemment.
try:
	print("Entry:",cfg_fast.functions[proj.entry])
except KeyError:
	print("No entry function")
#main_addr = proj.loader.main_bin.get_symbol("main").addr

# print("2^32-1=", (2**32)-1)
print("Min/max addresses:",proj.loader.min_addr,proj.loader.max_addr)

print("Analyses:",dir(proj.analyses))
print("Shared objects:",proj.loader.shared_objects)

