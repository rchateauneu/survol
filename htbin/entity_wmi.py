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

cgiEnv = lib_common.CgiEnv("WMI instance", can_process_remote=True)

( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()

cimomUrl = cgiEnv.GetHost()

# ON CHANGE TOUT A PARTIR D ICI:
# ON RETIRE LE HOST ET ON APPELLE WmiConnect(0 qui gere le cas ou c est la machine courante
# >>> w = wmi.WMI()
# >>> for x in w.query("select * from CIM_ComputerSystem where Name='rchateau-hp'"):  print x
# On gere les doublons.
# Exactement comme entity_wbem.
# Note: Le moniker accepte les classes de base donc de toute facon ca aurait ete.
# JE NE COMPRENDS PAS COMMENT CA A PU MARCHER JUSQU ICI.

# l affichage des proprietes est specifique a WMI , et donc la construcito d'un objet.
# on ne peut donc pas factoriser.

# On prend tout en meme temps car ca simplifie, mais par ailleurs on a besoin des elements separes.
# cgiMoniker = '\\\\RCHATEAU-HP\\root\\CIMV2:Win32_Process.Handle="3100"'
# cgiMoniker = '\\\\RCHATEAU-HP\\root\\CIMV2:Win32_NetworkAdapter.DeviceID="0"'

sys.stderr.write("cimomUrl=%s nameSpace=%s className=%s\n" % ( cimomUrl, nameSpace, className) )

rootNode = lib_util.EntityClassNode( className, nameSpace, cimomUrl, "WMI" )

grph = rdflib.Graph()

# Ca ne marche pas s'il y a un host !!
# cgiMoniker=\\WORKGROUP\RCHATEAU-HP\root\CIMV2:CIM_Process.Handle=7120 Caught:

# cgiMoniker='root\\CIMV2:CIM_System.Name="RCHATEAU-HP"'
# cgiMoniker='root\\CIMV2:CIM_Process.Handle="4796"'

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

def DispWmiProperties(grph,wmiInstanceNode,objWmi):
	for prp in objWmi.properties:
		# BEWARE, it could be None.
		value = getattr(objWmi,prp)

		# TODO: Add all usual Python types.
		if isinstance( value, ( unicode, int) ):
			# grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( value ) ) )
			# Special backslash replacement otherwise:
			# "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
			grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( str(value).replace('\\','\\\\') ) ) )
		elif isinstance( value, ( tuple) ):
			# grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( value ) ) )
			# Special backslash replacement otherwise:
			# "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
			cleanTuple = " ; ".join( [ oneVal.replace('\\','\\\\') for oneVal in value ] )
			grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( cleanTuple ) ) )
		elif value is None:
			grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( "None" ) ) )
		else:
			try:
				refMoniker = str( value.path() )
				refInstanceUrl = lib_util.EntityUrlFromMoniker( refMoniker )
				refInstanceNode = rdflib.term.URIRef(refInstanceUrl)
				grph.add( ( wmiInstanceNode, rdflib.Literal(prp), refInstanceNode ) )
			except AttributeError:
				exc = sys.exc_info()[1]
				grph.add( ( wmiInstanceNode, rdflib.Literal(prp), rdflib.Literal( str(exc) ) ) )

	wmiSubNode = wmiInstanceNode
	for clss in objWmi.derivation():
		wmiClassNode = lib_util.EntityClassNode( clss, nameSpace, cimomUrl, "WMI" )
		grph.add( ( wmiClassNode, pc.property_subclass, wmiSubNode ) )
		wmiSubNode = wmiClassNode

# Better use references() because it gives much more information.
#for assoc in objWmi.associators():
#	assocMoniker = str( assoc.path() )
#	sys.stderr.write("assocMoniker=[%s]\n" % assocMoniker )
#	assocInstanceUrl = lib_util.EntityUrlFromMoniker( assocMoniker )
#	assocInstanceNode = rdflib.term.URIRef(assocInstanceUrl)
#	grph.add( ( wmiInstanceNode, rdflib.Literal("assoc"), assocInstanceNode ) )


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

# Dont do this on a Win32_ComputerSystem object; it will take all day and kill your machine!
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
					grph.add( ( wmiInstanceNode, rdflib.Literal(keyPrp), refInstanceNode ) )
			except AttributeError:
				# Then it is a literal attribute.
				# TODO: Maybe we could test if the type is an instance.
				literalKeyValue[ keyPrp ] = str(valPrp)

		# Now the literal properties are attached to the other node.
		if refInstanceNode != None:
			for keyLitt in literalKeyValue:
				grph.add( ( refInstanceNode, rdflib.Literal(keyLitt), rdflib.Literal( literalKeyValue[ keyLitt ] ) ) )


# Try to read the moniker, which is much faster,
# but it does not always work if we do not have all the properties.
cgiMoniker = cgiEnv.GetParameters("xid")
sys.stderr.write("cgiMoniker=[%s]\n" % cgiMoniker )

# objList = None
objList = WmiReadWithMoniker( cgiEnv, cgiMoniker )
if objList is None:
	objList = WmiReadWithQuery( cgiEnv )

wmiInstanceUrl = lib_util.EntityUrlFromMoniker( cgiMoniker )
wmiInstanceNode = rdflib.term.URIRef(wmiInstanceUrl)

for objWmi in objList:
	sys.stderr.write("objWmi=[%s]\n" % str(objWmi) )

	# TODO: Attendre d'avoir plusieurs objects pour faire la meme chose que wentity_wbem,
	# c est a dire une deduplication adaptee avec creation d URL. Je me comprends.
	DispWmiProperties(grph,wmiInstanceNode,objWmi)

	if className not in ['Win32_ComputerSystem','PG_ComputerSystem','CIM_UnitaryComputerSystem','CIM_ComputerSystem','CIM_System','CIM_LogicalElement']:
		DispWmiReferences(grph,wmiInstanceNode,objWmi,cgiMoniker)

# TODO: Embetant car il faut le faire pour toutes les classes.
# Et en plus on perd le nom de la propriete.
# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",['root\\cimv2:CIM_Datafile'])
# 'PartComponent' for 'root\\cimv2:CIM_Datafile'
# 'Element' for 'root\\cimv2:Win32_DCOMApplication'
# 'Antecedent' for 'CIM_DataFile'
# cgiEnv.OutCgiRdf(grph,"LAYOUT_RECT",[rdflib.Literal('PartComponent'),rdflib.Literal('Element')])
cgiEnv.OutCgiRdf(grph,"",[rdflib.Literal('PartComponent'),rdflib.Literal('Element'),rdflib.Literal('Antecedent')])

"""
Convertir le moniker en moniker WBEM et "NOUS" et ajouter liens.
En plus, on va creer un entity_all.py qui synthetise les trois.
Il faut donc avoir un format unique pour les xid, cad les moniker.
On a donc une table qui passe du host netbios vers l url WBEM. Et s'il y a plusieurs urls WBEM ?
Netbios ou bien adresse IP ?
On suppose que les classes sont uniques quelque soit le namespace,
et qu'une classe ne peut pas apparaitre dans plusieurs namespaces (Meme supposition pour WMI).
Pour chaque serveur WBEM et peut etre aussi pour chaque machine WMI (Ou bien chaque version ?)
on a un dictionnaire qui pointe de la classe vers le namespace.
Pour chaque classe, on definit aussi les classes de bases qu on peut investiguer.


====================================================================================
>>> wmi.WMI().Win32_Process()[0].derivation()
(u'CIM_Process', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')

OpenLMI:
CIM_ManagedElement 	Instance Names 	Instances
|--- CIM_ManagedSystemElement 	Instance Names 	Instances
|    |--- CIM_LogicalElement
|    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
|    |    |    |--- CIM_Process 	Instance Names 	Instances
|    |    |    |    |--- CIM_UnixProcess 	Instance Names 	Instances
|    |    |    |    |    |--- TUT_UnixProcess 	Instance Names 	Instances

OpenPegasus/Windows:
CIM_ManagedElement 	Instance Names 	Instances
|--- CIM_ManagedSystemElement 	Instance Names 	Instances
|    |--- CIM_LogicalElement 	Instance Names 	Instances
|    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
|    |    |    |--- CIM_Process 	Instance Names 	Instances
|    |    |    |    |--- PG_UnixProcess 	Instance Names 	Instances

Quant a nous: "process" qui deviendra CIM_Process.

====================================================================================
Win32_Account:	Domain	Name

>>> wmi.WMI().Win32_UserAccount()[0].derivation()
(u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
>>> wmi.WMI().Win32_Group()[0].derivation()
(u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')

CIM_Account: 	CreationClassName 	Name 	SystemCreationClassName 	SystemName 	Namespace

OpenLMI:
CIM_ManagedElement 	Instance Names 	Instances
|--- CIM_ManagedSystemElement 	Instance Names 	Instances
|    |--- CIM_LogicalElement
|    |    |--- CIM_EnabledLogicalElement 	Instance Names 	Instances
|    |    |    |--- CIM_Account 	Instance Names 	Instances
|    |    |    |    |--- LMI_Account 	Instance Names 	Instances

CIM_ManagedElement 	Instance Names 	Instances
|--- CIM_Collection 	Instance Names 	Instances
|    |--- CIM_Group 	Instance Names 	Instances
|    |    |--- LMI_Group 	Instance Names 	Instances

OpenPegasus/Windows:
CIM_Account et CIM_Group pas definis sur OpenPegasus

WMI:
Win32_Group: "Distributed COM users","Guests", "Backup Operators" etc...
Win32_Account: Win32_Group + Win32_SystemAccount + Win32_UserAccount
Win32_UserAccount: "Administrator","Guest","HomeGroupUser$","rchateau"
Win32_SystemAccount : Tres intern a Windows, on peut laisser de cote.
Win32_GroupUser: "HomeUsers", "Administrator" : Associaton entre Win32_Group et un accoujnt

Quant a nous: "group" et "user"

On ne peut pas comparer directement, de totue facon, des accounts WMI et WBEM.
Mais notre ontologie doit faire la jonction avec WMI d'une part,
et WBEM d'autre part (Si Linux).
Une possibilite est de dupliquer nos directories.
En ce qui nous concerne, 2/3 du code est specifique Linux.

Quand on veut aller d'un objet portable (Process) vers un qui nest pas
portacle comme un user, il faut choisir dynamiquement le type:
Par exemple ici, Win32_UserAccount ou bien LMI_Account, qui n ont pas d ancetre commun.
Ou bien Win32_Group et LMI_Group.
On ne sait pas encore faire. Limitons-nous pour le moment aux cas sans ambiguites.


====================================================================================

>>> wmi.WMI().CIM_DataFile.derivation()
(u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
>>> wmi.WMI().Win32_Directory.derivation()
(u'CIM_Directory', u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')

OpenLMI:
CIM_ManagedElement 	Instance Names 	Instances
|--- CIM_ManagedSystemElement 	Instance Names 	Instances
|    |--- CIM_LogicalElement 	Instance Names 	Instances
|    |    |--- CIM_UnixFile 	Instance Names 	Instances
|    |    |    |--- LMI_UnixFile 	Instance Names 	Instances
|    |    |--- CIM_LogicalFile 	Instance Names 	Instances
|    |    |    |--- CIM_DataFile 	Instance Names 	Instances
|    |    |    |    |--- LMI_DataFile 	Instance Names 	Instances
|    |    |    |    |--- LMI_UnixSocket 	Instance Names 	Instances
|    |    |    |--- CIM_DeviceFile 	Instance Names 	Instances
|    |    |    |    |--- CIM_UnixDeviceFile 	Instance Names 	Instances
|    |    |    |    |    |--- LMI_UnixDeviceFile 	Instance Names 	Instances
|    |    |    |--- CIM_Directory 	Instance Names 	Instances
|    |    |    |    |--- CIM_UnixDirectory 	Instance Names 	Instances
|    |    |    |    |    |--- LMI_UnixDirectory 	Instance Names 	Instances
|    |    |    |--- CIM_FIFOPipeFile 	Instance Names 	Instances
|    |    |    |    |--- LMI_FIFOPipeFile 	Instance Names 	Instances
|    |    |    |--- CIM_SymbolicLink 	Instance Names 	Instances
|    |    |    |    |--- LMI_SymbolicLink 	Instance Names 	Instances

OpenPegasus/Windows:
Rien

====================================================================================

Jusqu'ou remonter ?
Un critere peut etre de remonter d abord dans notre classe, tant qu'on trouve notre propriete,
en l'occurence "Handle". Au-dessus, ca n'aurait pas de sens.
On peut selectionner les processes dans WIN et WBEM uniquement a partir de la classe CIM_Process.
Donc: On cherche la classe de base la plus elevee qui a toujours nos criteres.
Ensuite on cherche le namespace de cette classe dans le serveur d'en face (WMI ou WBEM),
on ajoute les memes criteres. Puis on fait la recherche.
Pour chaque type de serveur, il faudrait une fonction qui renvoie du RDF.

====================================================================================

Peut etre que entity_id pourrait etre soit une valeur unique: Si une seule clef,
ou bien un dictionnaire de paires clef-valeur.
Ne nous pressons pas: Dans un premier temps:
* Remplacer cimom=xxx par le moniker (En effet, c etait une erreur).
* Remplacer nos classes par des classes DMTF, avec mecanismes a rajouter.

"""
