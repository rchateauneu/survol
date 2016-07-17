#!/usr/bin/python

"""
TNSNAMES file
"""

import os
import sys
import re
import rdflib

import lib_util
import lib_common
from lib_properties import pc

###########################################################################################	
	
def parse_one(grph,database_dicts,database):
	# Get the database name and a set of (name, value) pairs.
	try:
		name = re.match(r'(\w+)', database).group(1)
	except AttributeError:
		# AttributeError: 'NoneType' object has no attribute 'group'
		# print("Cannot parse:"+database)
		return

	names_and_values = re.findall(r'(?i)([a-z]+)\s*=\s*([a-z0-9-\.]+)', database)
		
	# Build a dictionary from them, and if it has a HOST, add the IP.
	#'veyx': {'HOST': 'nykcmss3059.us.net.intra',
	#         'NAME': 'U016US',
	#         'PORT': '1521',
	#         'PROTOCOL': 'TCP',
	#         'SID': 'abcd',
	#         'SERVER': 'DEDICATED'},
	# The same pair host+socket can host several databases.
	database_dict = dict(names_and_values)

	try:
		node_addr = lib_common.gUriGen.AddrUri( database_dict['HOST'], database_dict['PORT'] )
	except KeyError:
		# pprint.pprint(database_dict)
		return
	
	# Here we should do something better, for example getting more information about this database.
	node_oradb = lib_common.gUriGen.OracleDbUri( name )

	grph.add( ( node_addr, pc.property_oracle_db, node_oradb ) )

	
def parse_all(grph, text):
	database_dicts = {}

	# Strip comments and blank lines.
	text = re.sub(r'#[^\n]*\n', '\n', text)
	text = re.sub(r'( *\n *)+', '\n', text.strip())
	
	# Split into database entries by balancing the parentheses.
	databases = []
	start = 0
	c = 0
	len_text = len(text)
	while c < len_text:
		parens = 0
		c = text.find('(',start)
		
		while c < len_text:
			text_c = text[c]
			c += 1
			if text_c == '(':
				parens += 1
			elif text_c == ')':
				parens -= 1
				if parens == 0:
					break
		
		parse_one( grph, database_dicts, text[start:c].strip() )

		start = c
	
	return database_dicts

###########################################################################################	

# ORAC_HOME=F:\ORAC\CLNT0010203NEN005\
# F:\ORAC\Config\tnsnames.ora
# "C:\Users\UK936025\AppData\Roaming\Microsoft\Windows\Recent\tnsnames.ora.lnk"
# http://www.dba-oracle.com/t_windows_tnsnames.ora_file_location.htm
# According to the docs, the precedence in which Oracle Net
# Configuration files are resolved is:
# Oracle Net files in present working directory (PWD/CWD)
# TNS_ADMIN set for each session session or by a user-defined script
# TNS_ADMIN set as a global environment variable
# TNS_ADMIN as defined in the registry
# Oracle Net files in %ORACLE_HOME/network/admin
#(Oracle default location)
# HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ORACLE\HOME3
# Name=TNS_ADMIN = F:\Orac\Config
#
# THIS DOES NTO WORK ANYMORE. NO IDEA WHY.
# "F:\ORAC\Config\tnsnames.ora"
#def FindTnsNamesWindowsOld():
#	try:
#		sys.stderr.write("FindTnsNamesWindowsOld ORAC_HOME=%s\n"%(os.environ['ORAC_HOME']))
#		aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
#		sys.stderr.write("FindTnsNamesWindowsOld\n")
#		aKey = OpenKey(aReg, r"SOFTWARE\Wow6432Node\ORACLE\HOME3")
#		for i in range(1024):
#			try:
#				sys.stderr.write("Before enumval\n")
#				n,v,t = EnumValue(aKey,i)
#				sys.stderr.write( str([ i, n,v,t ]) )
#				if n == 'TNS_ADMIN':
#					tns = v + "/tnsnames.ora"
#					return tns.replace( "\\", "/" )
#			except EnvironmentError:
#				exc = sys.exc_info()[1]
#				sys.stderr.write("FindTnsNamesWindowsOld caught %s\n"%(str(exc)))
#				return ""
#		CloseKey(aKey)
#		sys.stderr.write("After QueryValueEx\n")
#		return v
#	except Exception:
#		exc = sys.exc_info()[1]
#		sys.stderr.write("FindTnsNamesWindowsOld caught %s\n"%(str(exc)))
#		return ""

#		aKey = OpenKey(aReg, r"SOFTWARE\Wow6432Node\ORACLE\HOME3")
#		# http://stackoverflow.com/questions/5227107/python-code-to-read-registry
#		# What if there's more than 1024 sub-keys in "Uninstall"? Use *_winreg.QueryInfoKey(key)*
#		# HERE, WE LOOP MAYBE BECAUSE THERE ARE SEVERAL KEYS ?? Not sure.
#		for i in range(1024):
#			try:
#				asubkey_name=EnumKey(aKey,i)
#				sys.stderr.write("== asubkey_name=%d %s\n\r" % (i,asubkey_name) )
#				asubkey=OpenKey(aKey,asubkey_name)
#				if asubkey_name == 'TNS_ADMIN':
#					val=QueryValueEx(asubkey, "DisplayName")
#					sys.stderr.write("FindTnsNamesWindows val=%s\n"%(val))
#					return val
#			except EnvironmentError:
#				#sys.stderr.write("EnvironmentError\n")
#				#exc = sys.exc_info()[1]
#				#sys.stderr.write("FindTnsNamesWindows i=%d caught %s\n" % ( i , str(exc) ) )
#				#break
#				pass
#	except Exception:
#		exc = sys.exc_info()[1]
#		sys.stderr.write("FindTnsNamesWindows caught %s\n"%(str(exc)))
#		raise
#	return ""

#def FindTnsNamesOld():
#	sys.stderr.write("FindTnsNames platform=%s\n"%(sys.platform))
#
#	# For tests, if Oracle is not there, or if we do not want to use the real tnanames.ora.
#	# Strange logic for the base directory !!!
#	if lib_util.isPlatformWindows:
#		# "SimpleHTTP/0.6 Python/3.2.3": getcwd=D:\Projects\Divers\Reverse\PythonStyle
#		server_software = os.environ["SERVER_SOFTWARE"]
#		if server_software == "SimpleHTTP/0.6 Python/3.2.3":
#			python_style_dir = ""
#		# "Apache/2.0.65 (Win32)": getcwd=D:\Projects\Divers\Reverse\PythonStyle\htbin\internals
#		elif "Apache" in server_software:
#			python_style_dir = "../../../"
#		else:
#			python_style_dir = "../../../../"
#	else:
#		python_style_dir = "../../../../"
#
#	dflttnsnam = python_style_dir + "TestData/tnsnames.ora"
#
#	# dot.exe crashe avec le fichier BIG !!!
#	# return "TestData/tnsnames_BIG.ora"
#	return dflttnsnam
#
#	if lib_util.isPlatformWindows:
#		tnsnam = FindTnsNamesWindows()
#		if tnsnam == "":
#			tnsnam = dflttnsnam
#
#	if lib_util.isPlatformLinux:
#		try:
#			oracle_home = sys.environ['ORACLE_HOME']
#			tnsnam = oracle_home + '/network/admin/tnsnames.ora'
#		except:
#			tnsnam = dflttnsnam
#
#	sys.stderr.write("FindTnsNames tnsnam=%s\n" % tnsnam )
#	return tnsnam


# Key=HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\KEY_XE
# Name=ORACLE_HOME
# Data=C:\oraclexe\app\oracle\product\11.2.0\server
# "C:\oraclexe\app\oracle\product\11.2.0\server\network\ADMIN\tnsnames.ora"

def Main():
	cgiEnv = lib_common.CgiEnv()

	EXAMPLE = """\
	# www.virginia.edu/integratedsystem 1/16/04

	# Production 11.0.3 Apps instance
	prod = (DESCRIPTION=
			  (ADDRESS=(PROTOCOL=tcp)(HOST=isp-db.admin.Virginia.EDU)(PORT=1565))
			  (CONNECT_DATA=(SID=isp01))
		   )
	# Production 11.0.3 ODS instance
	ods = (DESCRIPTION=
			 (ADDRESS=(PROTOCOL=tcp)
				  (  HOST =
							isp-ods.admin.Virginia.EDU   )  # Whitespace test
					  (PORT=1565))
			 (CONNECT_DATA=(SID=isp01))
		  )
	"""

	grph = rdflib.Graph()


	if lib_util.isPlatformWindows:
		try:
			import winreg
		except ImportError:
			sys.stderr.write("winreg not available. Trying _winreg\n")
			try:
				import _winreg as winreg
			except ImportError:
				lib_common.ErrorMessageHtml("No winreg, cannot get tnsnames.ora location")

		# Tested with package _winreg.
		aReg = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
		try:
			aKey = winreg.OpenKey(aReg, r"SOFTWARE\Oracle\KEY_XE")
			# except WindowsError:
		except Exception: # Probably WindowsError but we must be portable.
			# The system cannot find the file specified
			try:
				# http://stackoverflow.com/questions/9348951/python-winreg-woes
				# KEY_WOW64_64KEY 64-bit application on the 64-bit registry view.
				# KEY_WOW64_32KEY 64-bit application on the 32-bit registry view.
				# Default is ( *,*, 0, winreg.KEY_READ )
				aKey = winreg.OpenKey(aReg, r"SOFTWARE\ORACLE\KEY_HOME4",0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
			except Exception: # Probably WindowsError but we must be portable.
				exc = sys.exc_info()[1]
				lib_common.ErrorMessageHtml("Caught %s" % str(exc))



		oraHome = None
		for i in range(1024):
			try:
				regVal=winreg.QueryValueEx(aKey, "ORACLE_HOME")
				oraHome=regVal[0]
				sys.stderr.write("FindTnsNamesWindows oraHome=%s\n" % str(oraHome) )
				break
			except EnvironmentError:
				break
		winreg.CloseKey(aKey)
		winreg.CloseKey(aReg)

		if oraHome is None:
			lib_common.ErrorMessageHtml("No ORACLE_HOME in registry, cannot get tnsnames.ora location")

		tnsnam = oraHome + "\\network\\ADMIN\\tnsnames.ora"

	elif lib_util.isPlatformLinux:
		tnsnam = ""

	else:
		lib_common.ErrorMessageHtml("No tnsnames.ora")

	###########################################################################################

	try:
		# Ca ne marche pas du tout, aucune idee pourquoi.
		# tnsnam = r"F:\Orac\Config\tnsnames.ora"
		# tnsnam=F:\Orac\Config\tnsnames.ora err=[Errno 2]
		# No such file or directory: 'F:\\Orac\\Config\\tnsnames.ora'
		# Beware that Apache might have no access right to it: 'F:\\Orac\\Config\\tnsnames.ora'
		sys.stderr.write("tnsnam=%s\n" % tnsnam)
		myfile = open(tnsnam,"r")
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("tnsnam="+tnsnam+" err="+str(exc))

	parse_all(grph, myfile.read())
	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
