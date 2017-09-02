import lib_common


# /usr/lib/modules/4.1.4-200.fc22.x86_64/kernel/drivers/media/usb/gspca/stv06xx/gspca_stv06xx.ko.xz

# This can work on Linux only.
def KernelVersion():
	version_file = open("/proc/version","r")
	version_line = version_file.read()
	version = version_line.split(' ')[2]
	return version

def ModulesDepsFilename():
	version = KernelVersion()

	# /lib/modules/4.1.4-200.fc22.x86_64/modules.dep
	module_deps_name = "/lib/modules/" + version + "/modules.dep"

	return module_deps_name

def Prefix():
	return "/usr/lib/modules/" + KernelVersion() + "/"

# TODO: Hide this !!
gblDictModules = dict()

def ModuleToNode(modnam):
	global gblDictModules
	try:
		return gblDictModules[modnam]
	except KeyError:
		nod = lib_common.gUriGen.FileUri(modnam)
		gblDictModules[modnam] = nod
		return nod

def Dependencies():
	result = dict()

	kernel_prefix = Prefix()

	module_deps_name = ModulesDepsFilename()

	modules_file = open(module_deps_name,"r")
	for modules_line in modules_file:
		modules_split_colon = modules_line.split(':')
		module_name = modules_split_colon[0]
		module_name = kernel_prefix + module_name

		module_deps_list = modules_split_colon[1].split(' ')

		files_list = []
		for module_dep in module_deps_list:
			module_dep = module_dep.strip()
			if module_dep == "":
				continue

			module_dep = kernel_prefix + module_dep
			files_list.append( module_dep )
			
		result[ module_name ] = files_list

	modules_file.close()
	return result





