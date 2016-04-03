#!/usr/bin/python

# TEMPORARILLY USED BECAUSE WE MIGHT USE ONLY THE SAME SCRIPT FOR EVERYONE.
# This is experimental to ensure that we can process WMI objects,
# in a plain WMI context: Keys, monikers etc...
# It cannot harm and will be kept. Contains many notes.


"""
Display a WMI entity or instance.
"""

import sys
import psutil
import socket
import rdflib
import lib_common
import lib_wmi
import lib_util
from lib_properties import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("WMI Python library not installed")

paramkeyDisplayNone = "Display none values"
cgiEnv = lib_common.CgiEnv("WMI instance", can_process_remote=True,
								parameters = { paramkeyDisplayNone : "0" })

displayNoneValues = cgiEnv.GetParameters( paramkeyDisplayNone ) in ( "1", "Y", "True")

( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()

cimomUrl = cgiEnv.GetHost()

sys.stderr.write("cimomUrl=%s nameSpace=%s className=%s\n" % ( cimomUrl, nameSpace, className) )

grph = rdflib.Graph()

sys.stderr.write("cgiEnv.m_entity_id=%s\n" % cgiEnv.m_entity_id)

connWmi = lib_wmi.WmiConnect(cimomUrl,nameSpace)

def WmiReadWithMoniker( cgiEnv, cgiMoniker ):
	try:
		# cgiMoniker = cgiEnv.GetXid()[0]
		# lib_common.ErrorMessageHtml("cgiMoniker=%s" % ( cgiMoniker ) )
		objWmi = wmi.WMI(moniker=cgiMoniker)
		return [ objWmi ]
	except Exception:
		exc = sys.exc_info()[1]
		sys.stderr.write("cgiMoniker=%s Caught:%s\n" % ( cgiMoniker, str(exc) ) )
		return None

# Maybe reading with the moniker does not work because not all properties.
def WmiReadWithQuery( cgiEnv ):
	splitMonik = lib_util.SplitMoniker( cgiEnv.m_entity_id )
	aQry = lib_util.SplitMonikToWQL(splitMonik,className)

	try:
		return connWmi.query(aQry)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Query=%s Caught:%s" % ( aQry, str(exc) ) )

# TODO: Add all usual Python types.
if sys.version_info >= (3,):
	listTypes = ( str, int, float )
else:
	listTypes = ( unicode, int, float )

# Displays the properties of a WMI object (Not a class).
def DispWmiProperties(grph,wmiInstanceNode,objWmi):
	for prp in objWmi.properties:
		# BEWARE, it could be None.
		value = getattr(objWmi,prp)

		if isinstance( value, listTypes ):
			# Special backslash replacement otherwise:
			# "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
			grph.add( ( wmiInstanceNode, lib_common.MakeProp(prp), rdflib.Literal( str(value).replace('\\','\\\\') ) ) )
		elif isinstance( value, ( tuple) ):
			# Special backslash replacement otherwise:
			# "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
			cleanTuple = " ; ".join( [ str(oneVal).replace('\\','\\\\') for oneVal in value ] )
			grph.add( ( wmiInstanceNode, lib_common.MakeProp(prp), rdflib.Literal( cleanTuple ) ) )
		elif value is None:
			if displayNoneValues:
				grph.add( ( wmiInstanceNode, lib_common.MakeProp(prp), rdflib.Literal( "None" ) ) )
		else:
			try:
				refMoniker = str( value.path() )
				refInstanceUrl = lib_util.EntityUrlFromMoniker( refMoniker )
				refInstanceNode = rdflib.term.URIRef(refInstanceUrl)
				grph.add( ( wmiInstanceNode, lib_common.MakeProp(prp), refInstanceNode ) )
			except AttributeError:
				exc = sys.exc_info()[1]
				grph.add( ( wmiInstanceNode, lib_common.MakeProp(prp), rdflib.Literal( str(exc) ) ) )


# Better use references() because it gives much more information.
#for assoc in objWmi.associators():
#	assocMoniker = str( assoc.path() )
#	sys.stderr.write("assocMoniker=[%s]\n" % assocMoniker )
#	assocInstanceUrl = lib_util.EntityUrlFromMoniker( assocMoniker )
#	assocInstanceNode = rdflib.term.URIRef(assocInstanceUrl)
#	grph.add( ( wmiInstanceNode, lib_common.MakeProp("assoc"), assocInstanceNode ) )


"""
Traduire les uri de wbem vers wmi et vers nous etc...
Les namespaces sont case-sensitive sous Unix au contraire de WMI.
On doit passer de WMI a WBEM et recioproauement.
Mais en interne, il faut un seul type d'URI sinon ca ne peut pas fusionner.
On peut avoir une table de mapping en interne pour les machines.
Pour les namespaces c'est plus complique:
Il faut utiliser la classe qui mappe vers son namespaces.
Donc on garde pour WBEM et WMI le mapping classe=>namespace.
Ce mapping est fait au premier appel, et on s'en sert aussi pour l affichage.

"""
# TESTS:
# OK
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="rchateau-hp"')
# _wmi_object: \\RCHATEAU-HP\root\CIMV2:Win32_ComputerSystem.Name="rchateau-hp">
# KAPUTT
# wmi.WMI(moniker='\\rchateau-HP\root\CIMV2:CIM_ComputerSystem.Name="rchateau-hp"')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name=rchateau-hp')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="127.0.0.1"')



# WmiExplorer displays the namespace as: "ROOT\CIMV2"
#
# The namespace is converted to lowercase, no idea why.
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa389766%28v=vs.85%29.aspx
# The __Namespace system class has a single property called Name,
# which must be unique within the scope of the parent namespace.
# The Name property must also contain a string that begins with a letter.
# All other characters in the string can be letters, digits, or underscores.
# All characters are case-insensitive.
# refMoniker='\\RCHATEAU-HP\root\cimv2:CIM_DataFile.Name="c:\\windows\\system32\\sspicli.dll"'
# cgiMoniker='\\RCHATEAU-HP\root\CIMV2:CIM_DataFile.Name="c:\\windows\\system32\\sspicli.dll"'
#
# '\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="RCHATEAU-HP",Name="Administrator"'
# '\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="Administrator"'
#
def EqualMonikers( monikA, monikB ):
	splitA = monikA.split(':')
	splitB = monikB.split(':')

	# Maybe we could simply make a case-insensitive string comparison.
	return splitA[0].upper() == splitB[0].upper() and splitA[1:].upper() == splitB[1:].upper()

# Dont do this on a Win32_ComputerSystem object and several other classes; it is VERY SLOW !
# TODO: Test with a small data set.
def DispWmiReferences(grph,wmiInstanceNode,objWmi,cgiMoniker):
	for objRef in objWmi.references():
		literalKeyValue = dict()
		refInstanceNode = None
		for keyPrp in objRef.properties:
			valPrp = getattr(objRef,keyPrp)
			try:
				# references() have one leg pointing to the current object,
				refMoniker = str( valPrp.path() )

				# Maybe it would be better to compare the objects ???
				if not EqualMonikers( refMoniker, cgiMoniker ):
					# TODO: Disabled for the moment because we do not understand the logic.
					if False and refInstanceNode is not None:
						# TODO: Pourquoi ceci ????????????
						# Inconsistency:\\RCHATEAU-HP\root\cimv2:Win32_LogonSession.LogonId="195361" != \\192.168.1.83\root\CIMV2:CIM_Process.Handle=7120
						lib_common.ErrorMessageHtml("Inconsistency:"+refMoniker + " != " + cgiMoniker )
					refInstanceUrl = lib_util.EntityUrlFromMoniker( refMoniker )
					refInstanceNode = rdflib.term.URIRef(refInstanceUrl)
					grph.add( ( wmiInstanceNode, lib_common.MakeProp(keyPrp), refInstanceNode ) )
			except AttributeError:
				# Then it is a literal attribute.
				# TODO: Maybe we could test if the type is an instance.
				# Beware: UnicodeEncodeError: 'ascii' codec can't encode character u'\\u2013'
				try:
					literalKeyValue[ keyPrp ] = str(valPrp)
				except UnicodeEncodeError:
					literalKeyValue[ keyPrp ] = "UnicodeEncodeError"


		# Now the literal properties are attached to the other node.
		if refInstanceNode != None:
			for keyLitt in literalKeyValue:
				grph.add( ( refInstanceNode, lib_common.MakeProp(keyLitt), rdflib.Literal( literalKeyValue[ keyLitt ] ) ) )




# Try to read the moniker, which is much faster,
# but it does not always work if we do not have all the properties.
cgiMoniker = cgiEnv.GetParameters("xid")
sys.stderr.write("cgiMoniker=[%s]\n" % cgiMoniker )

objList = WmiReadWithMoniker( cgiEnv, cgiMoniker )
if objList is None:
	objList = WmiReadWithQuery( cgiEnv )

wmiInstanceUrl = lib_util.EntityUrlFromMoniker( cgiMoniker )
wmiInstanceNode = rdflib.term.URIRef(wmiInstanceUrl)

for objWmi in objList:
	# sys.stderr.write("objWmi=[%s]\n" % str(objWmi) )

	# TODO: Attendre d'avoir plusieurs objects pour faire la meme chose que wentity_wbem,
	# c est a dire une deduplication adaptee avec creation d URL. Je me comprends.
	DispWmiProperties(grph,wmiInstanceNode,objWmi)

	# TODO: Pour ces classes, l'attente est tres longue. Rather create another link.
	# rchref = wmi.WMI().query("select * from Win32_UserAccount where Name='rchateau'")[0].references()
	# Several minutes for 139 elements.
	if not lib_wmi.WmiTooManyInstances( className ):
		try:
			DispWmiReferences(grph,wmiInstanceNode,objWmi,cgiMoniker)
		except:
			exc = sys.exc_info()[1]
			sys.stderr.write("Exception=%s\n" % str(exc) )
	else:
		grph.add( ( wmiInstanceNode, lib_common.MakeProp("REFERENCES"), rdflib.Literal( "DISABLED" ) ) )

# Adds the qualifiers of this class.
klassObj = getattr( connWmi, className )

wmiSubNode = wmiInstanceNode

# It always work even if there is no object.
for baseKlass in klassObj.derivation():
	wmiClassNode = lib_util.EntityClassNode( baseKlass, nameSpace, cimomUrl, "WMI" )
	grph.add( ( wmiClassNode, pc.property_subclass, wmiSubNode ) )

	lib_wmi.WmiAddClassQualifiers( grph, connWmi, wmiClassNode, baseKlass )
	wmiSubNode = wmiClassNode

#grph.add( ( rootNode, lib_common.MakeProp(className), wmiInstanceNode ) )
#
#for clss in objWmi.derivation():
#	wmiClassNode = lib_util.EntityClassNode( clss, nameSpace, cimomUrl, "WMI" )
#	grph.add( ( wmiClassNode, pc.property_subclass, wmiSubNode ) )
#	wmiSubNode = wmiClassNode



# TODO: Embetant car il faut le faire pour toutes les classes.
# Et en plus on perd le nom de la propriete.
# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",['root\\cimv2:CIM_Datafile'])
# 'PartComponent' for 'root\\cimv2:CIM_Datafile'
# 'Element' for 'root\\cimv2:Win32_DCOMApplication'
# 'Antecedent' for 'CIM_DataFile'
cgiEnv.OutCgiRdf(grph,"LAYOUT_TWOPI",[lib_common.MakeProp('PartComponent'),lib_common.MakeProp('Element'),lib_common.MakeProp('Antecedent')])
# cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE",[lib_common.MakeProp('PartComponent'),lib_common.MakeProp('Element'),lib_common.MakeProp('Antecedent')])

