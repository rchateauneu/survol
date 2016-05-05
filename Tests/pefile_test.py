import pefile
import sys
import time
import os
import os.path
import win32api


# Maybe use this to display, on the fly, more information about DLLs.


# def get_file_ver(fname):
# 	# see: http://pywin32.hg.sourceforge.net/hgweb/pywin32/pywin32/file/tip/win32/Demos/getfilever.py
# 	result = []
# 	try:
# 		ver_strings = ('ProductVersion', 'FileVersion')
# 		pairs = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')
# 		## \VarFileInfo\Translation returns list of available (language, codepage) pairs that can be used to retreive string info
# 		## any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle two are language/codepage pair returned from above
# 		for lang, codepage in pairs:
# 			#print 'lang: ', lang, 'codepage:', codepage
# 			for ver_string in ver_strings:
# 				str_info = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, ver_string)
# 				result.append('%s %s' % (ver_string, win32api.GetFileVersionInfo(fname, str_info).strip()))
# 	except:
# 		pass
# 	return result


#def which(fname,isLong=False):
#	"""searches fname in PATH dirs"""
#	if not which_file(fname,isLong):
#		if '.' not in fname:
#			# no extension, so we try some "executable" extensions
#			for ext in ('.exe', '.com', '.bat', '.cmd'):
#				fname2 = fname + ext
#				if which_file(fname2,isLong):
#					break




# def which_file(fname,margin):
# 	"""prints paths for fname where fname can be found, in case of .dll loads it"""
# 	files = []
# 	dirs_norm = []
# 	dirs_l = []
# 	for d in dirs:
# 		dn = d.lower()
# 		if dn not in dirs_l:
# 			dirs_l.append(dn)
# 			dirs_norm.append(d)
# 	for d in dirs_norm:
# 		fname2 = os.path.join(d, fname)
# 		if os.path.exists(fname2):
# 			if fname2 not in files:
# 				files.append(fname2)
# 	if files:
# 		for fi in files:
# 			deps( fi, margin + "    ")
# 	h = 0
# 	if fname.lower().endswith('.dll'):
# 		try:
# 			h = win32api.LoadLibrary(fname)
# 			if h:
# 				dll_name = win32api.GetModuleFileName(h)
# 		except:
# 			print('\tCannot load "%s" !!!' % (fname))

# https://recon.cx/en/f/lightning-ecarrera-win32-static-analysis-in-python.pdf

path = win32api.GetEnvironmentVariable('PATH')
# try paths as described in MSDN
dirs = [os.getcwd(), win32api.GetSystemDirectory(), win32api.GetWindowsDirectory()] + path.split(';')

dirs_norm = []
dirs_l = []
for d in dirs:
	dn = d.lower()
	if dn not in dirs_l:
		dirs_l.append(dn)
		dirs_norm.append(d)

cache_dll_to_imports = dict()

def deps(finam,margin):
	finam = finam.lower()
	print(margin+finam)

	if finam in cache_dll_to_imports:
		filist = cache_dll_to_imports[finam]
		return
	else:
		filist = []
		pe = pefile.PE(finam)

		try:
			for entry in pe.DIRECTORY_ENTRY_IMPORT:
				for d in dirs_norm:
					fname2 = os.path.join(d, entry.dll)
					if os.path.exists(fname2):
						filist.append(fname2)
						break
		except AttributeError:
			pass
			# print(margin + finam + " NO_ENTRY	")
		cache_dll_to_imports[finam] = filist

	for fname2 in filist:
		deps( fname2, margin + "    ")

deps(sys.argv[1],"=   ")