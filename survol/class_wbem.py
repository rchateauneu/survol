#!/usr/bin/python

"""
WBEM class portal: Display all instances of a given WBEM class
"""

import sys
import cgi
import urllib
import lib_util
import lib_common
import lib_wbem
from lib_properties import pc

import pywbem # Might be pywbem or python3-pywbem.


#EnumerateInstanceNames: nameSpace=root/cimv2 className=TUT_ProcessChild. Caught:(1, u'CIM_ERR_FAILED: cmpi:Traceback (most recent call last):
#File "/usr/lib64/python2.7/site-packages/cmpi_pywbem_bindings.py", line 82, in __call__
#return self.meth(*args, **kwds)
#File "/usr/lib64/python2.7/site-packages/cmpi_pywbem_bindings.py", line 483, in enum_instance_names
#for i in self.proxy.MI_enumInstanceNames(env, op):
#File "/usr/lib/python2.7/site-packages/pywbem/cim_provider2.py", line 499, in MI_enumInstanceNames
#for inst in gen:
#File "/home/rchateau/TestProviderOpenLMI/tutorial_final/TUT_ProcessChild.py", line 152, in enum_instances
#(name, ppid, exe, args) = ps.get_process_info(pid)
#File "/home/rchateau/TestProviderOpenLMI/tutorial_final/ps.py", line 15, in get_process_info
#lines = open(statuspath).readlines()
#IOError: [Errno 2] No such file or directory: \'/proc/15480/status\'')
#Cwd	C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin
#OS	win32
#Version	2.7.10 (default, May 23 2015, 09:44:00) [MSC v.1500 64 bit (AMD64)]
#Check environment variables.
#Return home.

# ATTENTION: Si les lignes de titres sont trop longues, graphviz supprime des lignes de la table HTML !!!!!!!
# ET CA NE TIEN TPAS LA CHARGE !!!!!!!!!!!!!!!
# maxCnt = 70,72,75,80,81
# 82,85,90,100 : Tres long.
# HARDCODE_LIMIT


def AssocReferenceToNode(nameSpace,entity_host,assocInst):
	assocClass = assocInst.classname

	assocKeyValPairs = assocInst.keybindings

	# The natural conversion to a string makes a perfect url, But we need to extract the components:
	# str(valAssoc) = 'root/cimv2:LMI_DiskDrive.CreationClassName="LMI_DiskDrive",SystemName="Unknown-30-b5-c2-02-0c-b5-2.home"'

	assoc_entity_id = ",".join( "%s=%s" % ( k, assocKeyValPairs[k] ) for k in assocKeyValPairs )

	# The association and the references are probably in the same namespace.
	wbemAssocUrl = lib_wbem.WbemInstanceUrl( nameSpace, assocClass, assoc_entity_id, entity_host )
	wbemAssocNode = lib_common.NodeUrl(wbemAssocUrl)
	return wbemAssocNode

# Display the graph of associations.
# It can work only if there are only two references in each instance.
def DisplayAssociatorsAsNetwork(grph,inst_names,rootNode,nameSpace,entity_host,maxInstances,startIndex):
	maxCnt = 0
	for iname in inst_names:
		if startIndex > 0:
			startIndex -= 1
			continue

		if maxCnt == maxInstances:
			break
		maxCnt += 1

		# For the moment, references are not added to the Moniker, otherwise the syntax would be too complicated, like:
		# wbemInstName=root/CIMv2:TUT_ProcessChild.Parent="root/cimv2:TUT_UnixProcess.Handle="1"",Child="root/cimv2:TUT_UnixProcess.Handle="621"",OSCreationClassName="Linux_OperatingSystem",CSName="Unknown-30-b5-c2-02-0c-b5-2.home",CSCreationClassName="Linux_ComputerSystem",CreationClassName="TUT_UnixProcess",OSName="Unknown-30-b5-c2-02-0c-b5-2.home"

		# Do not care about the instance.

		nodePrevious = None
		keyPrevious = None

		for keyAssoc in iname.keys():
			assocInst = iname[keyAssoc]

			# If this happens, it could be used as a qualifier for the edge.
			if not isinstance( assocInst, pywbem.CIMInstanceName ):
				lib_common.ErrorMessageHtml("Inconsistency, members should be instances: __name__=%s" % type(assocInst).__name__)

			wbemAssocNode = AssocReferenceToNode(nameSpace,entity_host,assocInst)

			# We lose the name of the previous property.
			if not nodePrevious is None:
				grph.add( ( nodePrevious, lib_common.MakeProp(keyPrevious + "-" + keyAssoc), wbemAssocNode ) )

			keyPrevious = keyAssoc
			nodePrevious = wbemAssocNode


# Display one line per instance of the class as members were literals.
# This attempts to display the references as links. It does not really work yet,
# because "special" properties" have to be used.
def DisplayAssociatorsAsList(grph,inst_names,rootNode,nameSpace,entity_host, className,maxInstances,startIndex):
	maxCnt = 0
	for iname in inst_names:
		if startIndex > 0:
			startIndex -= 1
			continue

		if maxCnt == maxInstances:
			break
		maxCnt += 1

		# For the moment, references are not added to the Moniker, otherwise the syntax would be too complicated, like:
		# wbemInstName=root/CIMv2:TUT_ProcessChild.Parent="root/cimv2:TUT_UnixProcess.Handle="1"",Child="root/cimv2:TUT_UnixProcess.Handle="621"",OSCreationClassName="Linux_OperatingSystem",CSName="Unknown-30-b5-c2-02-0c-b5-2.home",CSCreationClassName="Linux_ComputerSystem",CreationClassName="TUT_UnixProcess",OSName="Unknown-30-b5-c2-02-0c-b5-2.home"

		entity_id = ",".join( "%s=%s" % ( k, iname[k] ) for k in iname.keys() )

		wbemInstanceUrl = lib_wbem.WbemInstanceUrl( nameSpace, className, entity_id, entity_host )
		wbemInstanceNode = lib_common.NodeUrl(wbemInstanceUrl)

		# On va ajouter une colonne par reference.
		for keyAssoc in iname.keys():
			assocInst = iname[keyAssoc]

			wbemAssocNode = AssocReferenceToNode(nameSpace,entity_host,assocInst)
			grph.add( ( wbemInstanceNode, lib_common.MakeProp(keyAssoc), wbemAssocNode ) )

			# On voudrait que la propriete soit un lien mais que ca soit afficher en colonne avec le bon nom, comme in lityeral.
			# pc.property_rdf_data_nolist1 ??? pc.property_rdf_data_nolist1, pc.property_rdf_data_nolist2 ?????

			### TODO: BUG DAND L AFFICHAGE, DESFOIS CA RELIE AU NODE, DESFOIS CA RELIE A UN nd_0

		grph.add( ( rootNode, pc.property_class_instance, wbemInstanceNode ) )

		# TODO: PAS ICI, on va le mettre dans l ;affichage d une entite.
		#for key,val in iname.iteritems():
		#	grph.add( ( wbemInstanceNode, lib_common.MakeProp(key), lib_common.NodeLiteral(val) ) )

# Display one line per instance of the class. Members are literals
# because this is not an associator. Still, it works with an associator.
def DisplayPlainClass(grph,inst_names,rootNode,nameSpace,entity_host, className,maxInstances,startIndex):
	maxCnt = 0

	# This is for normal classes.
	for iname in inst_names:
		if startIndex > 0:
			startIndex -= 1
			continue

		if maxCnt == maxInstances:
			break
		maxCnt += 1

		# This concatenates all the properties, even the ones which are not in the Survol ontology.
		# This makes sense because we do not know if this class if known by Survol.
		entity_id = ",".join( "%s=%s" % ( k, iname[k] ) for k in iname.keys() )
		wbemInstanceUrl = lib_wbem.WbemInstanceUrl( nameSpace, className, entity_id, entity_host )

		wbemInstanceNode = lib_common.NodeUrl(wbemInstanceUrl)

		grph.add( ( rootNode, pc.property_class_instance, wbemInstanceNode ) )


def Main():
	paramkeyMaxInstances = "Max instances"
	paramkeyStartIndex = "Start index"

	# This can process remote hosts because it does not call any script, just shows them.
	cgiEnv = lib_common.CgiEnv(can_process_remote = True,
									parameters = { paramkeyMaxInstances : 80, paramkeyStartIndex: 0 })

	maxInstances = cgiEnv.GetParameters( paramkeyMaxInstances )
	startIndex = cgiEnv.GetParameters( paramkeyStartIndex )

	grph = cgiEnv.GetGraph()

	( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
	sys.stderr.write("nameSpace=%s className=%s entity_namespace_type=%s\n" % ( nameSpace, className, entity_namespace_type ) )

	entity_host = cgiEnv.GetHost()

	rootNode = lib_util.EntityClassNode( className, nameSpace, entity_host, "WBEM" )

	# Hard-coded default namespace.
	if nameSpace == "":
		nameSpace = "root/CIMV2"

	# This adds a link to the namespace of this WBEM class: It shows its inheritance graph.
	urlNamespace = lib_wbem.NamespaceUrl( nameSpace, entity_host, className )
	nodNamespace = lib_common.NodeUrl( urlNamespace )
	grph.add( ( rootNode, pc.property_cim_subnamespace , nodNamespace ) )

	try:
		connWbem = lib_wbem.WbemConnection(entity_host)
		wbemKlass = connWbem.GetClass(className, namespace=nameSpace, LocalOnly=False, IncludeQualifiers=True)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("EnumerateInstanceNames: entity_host="+entity_host+" nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc))

	klaDescrip = lib_wbem.WbemClassDescrFromClass(wbemKlass)
	grph.add( ( rootNode, pc.property_information, lib_common.NodeLiteral("WBEM description: "+klaDescrip ) ) )

	# Pour afficher du texte: Remplacer le help statique.
	# offset va etre un parametre. Helas ne pas se fairew d illusions sur "offset"

	# WBEM and WMI both have the annoying limitation that it is not possible to select only a range of instances.
	try:
		inst_names = connWbem.EnumerateInstanceNames(ClassName=className,namespace=nameSpace)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("EnumerateInstanceNames: entity_host="+entity_host+" nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc))

	try:
		isAssociation = wbemKlass.qualifiers['Association'].value
	except KeyError:
		isAssociation = False

	# It is possible to display an association like a normal class but it is useless.
	if isAssociation:
		if True:
			DisplayAssociatorsAsNetwork(grph,inst_names,rootNode,nameSpace,entity_host,maxInstances,startIndex)
		else:
			DisplayAssociatorsAsList(grph,inst_names,rootNode,nameSpace,entity_host, className,maxInstances,startIndex)
	else:
		DisplayPlainClass(grph,inst_names,rootNode,nameSpace,entity_host, className,maxInstances,startIndex)

	numInstances = len(inst_names)
	sys.stderr.write("numInstances=%d startIndex=%d\n"%(numInstances,startIndex))

	# This displays one link on the same page, with specific values of these parameters.
	# The other parameters are not changed.
	# TODO, BEWARE: What is the total number of elements ?
	if startIndex + maxInstances < numInstances:
		cgiEnv.AddParameterizedLinks( "Next", { paramkeyStartIndex: startIndex + maxInstances } )
	if startIndex > 0:
		cgiEnv.AddParameterizedLinks( "Previous", { paramkeyStartIndex: max(startIndex - maxInstances,0) } )


	# TODO: On pourrait rassembler par classes,
	# et aussi afficher les liens d'heritages des classes.


	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_class_instance])

if __name__ == '__main__':
	Main()
