#!/usr/bin/python

"""
WMI namespaces.
"""

import sys
import lib_util
import lib_common
import rdflib
from lib_properties import pc
try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("Python package WMI is not available")
import lib_wmi

# TODO: Hard-coded list for the moment because we could not find a way
# to list "root" subnamespaces with wmi. Not a problem for the moment.
# http://stackoverflow.com/questions/5332501/how-do-you-query-for-wmi-namespaces
hardcodedNamespaces = (
	"aspnet",        # Not on Toshiba Win8
	"CIMV2",
	"Cli",           # This does not work on Windows XP
	"Default",
	"directory",
	"Hardware",      # Toshiba Win8
	"HP",            # Not on Toshiba Win8
	"Interop",
	"Microsoft",
	"msdtc",         # Toshiba Win8
	"nap",
	"Policy",        # Not on Toshiba Win8
	"RSOP",
	"SECURITY",      # Not on HP Win7
	"SecurityCenter",
	"SecurityCenter2",
	"ServiceModel",  # Not on Toshiba Win8 nor HP Win7
	"StandardCimv2", # Toshiba Win8
	"subscription",
	"WMI",           # Toshiba Win8 and HP Win7
)



def SubNamespace( rootNode, grph, nskey, cimomUrl ):
	try:
		# connWMI = lib_wmi.WmiConnect(cimomUrl,nskey)
		connWMI = lib_wmi.WmiConnect(cimomUrl,"root\\" + nskey)
	except wmi.x_wmi:
		exc = sys.exc_info()[1]
		# lib_common.ErrorMessageHtml("EXCEPT WMI nskey=%s Caught:%s" % ( nskey , str(exc) ) )
		sys.stderr.write("WMI: Cannot connect to nskey=%s Caught:%s" % ( nskey , str(exc) ) )
		return

	# connWMI = lib_wmi.WmiConnect(cimomUrl,nskey)

	wmiUrl = lib_wmi.NamespaceUrl( "root\\" + nskey, cimomUrl )
	wmiNode = rdflib.term.URIRef( wmiUrl )

	grph.add( ( rootNode, pc.property_cim_subnamespace, wmiNode ) )

	try:
		for subnamespace in connWMI.__NAMESPACE():
			SubNamespace( wmiNode, grph, nskey + "\\" + subnamespace.Name, cimomUrl )
	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( wmiNode, pc.property_information, rdflib.Literal("Caught:%s" % str(exc) ) ) )
		# lib_common.ErrorMessageHtml("nskey=%s Caught:%s" % ( nskey , str(exc) ) )

def Main():
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)

	# See differences and similarities between these.
	# entity_host = cgiEnv.GetHost()
	# entity_host = cgiEnv.GetParameters("xid")
	entity_host = cgiEnv.GetHost()

	sys.stderr.write("entity_host=%s\n" % entity_host)
	entity_host = lib_wmi.NormalHostName(entity_host)

	cimomUrl = entity_host

	sys.stderr.write("cimomUrl=%s\n" % cimomUrl)

	grph = rdflib.Graph()

	# There is no consensus on the WMI class for namespaces,
	# so we have ours which must be correctly mapped.
	namespace_class = "wmi_namespace"
	rootNode = lib_util.EntityUri(namespace_class,"")



	##########  test seulement
	# Unexpected COM Error (-2147023174, 'The RPC server is unavailable.', None, None)

	# Erreur possible si on se connecte a l adresse courante:
	# 'SWbemLocator', u'User credentials cannot be used for local connections '

	# http://timgolden.me.uk/python/wmi/tutorial.html
	# connWMI = lib_wmi.WmiConnect(cimomUrl,"Microsoft")
	# connWMI = wmi.WMI("192.168.1.67",user="rchateau", password="kennwert") # The RPC server is unavailable
	# connWMI = wmi.WMI("192.168.1.78",user="vero", password="wimereux62") # The RPC server is unavailable
	# c = wmi.WMI(namespace="WMI")
	#
	# c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")


	for nskey in hardcodedNamespaces:
		# SubNamespace( rootNode, grph, nskey )
		try: # "root\\" +
			# SubNamespace( rootNode, grph, nskey, cimomUrl )
			SubNamespace( rootNode, grph, nskey, cimomUrl )
		#except wmi.x_wmi:
		#	exc = sys.exc_info()[1]
		#	lib_common.ErrorMessageHtml("EXCEPT WMI nskey=%s Caught:%s" % ( nskey , str(exc) ) )
		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("nskey=%s Caught:%s" % ( nskey , str(exc) ) )

	cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT", [pc.property_cim_subnamespace])
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
