import lmi
import lmi.shell
import sys

#Pour lmi, i faut avoir installe les packages.
# Pour le moment on se borne a pywbem dans la mseure ou
# on est certain de pouvoir l installer sous Windows et Linux.

# Apparemmemt on peut installer, on va voir si c est moins bugge,
# plus rapide et mieux maintenu que pywbem.
# Si c est le cas, on va le choisir mais faudra laisser tomber yawn.

# import lmi.shell
# Dependance: Il faut le module python readline.
# C:\Users\rchateau\Downloads\readline-6.2.4.1>PYTHON SETUP.PY INSTALL
# error: this module is not meant to work on Windows

def TestOPENLMI():
	print "Hello"
	c = lmi.shell.connect("http://192.168.1.88", "pegasus", "toto")

	ns = c.namespaces
	
	xx = c.root.cimv2.LMI_ServiceAffectsIdentity
	
	nbxx = len(c.root.cimv2.LMI_ServiceAffectsIdentity.instances())
	print "Il y en a %d" % nbxx
	
	#clslist = c.root.cimv2.classes()
	
	#print "Nb classes=%d" % len(clslist)
	#print clslist
	
	hangingClasses = [
		"CIM_ServiceAffectsElement",
		"LMI_ResourceForSoftwareIdentity",
		"LMI_SoftwareIdentity",
		"CIM_SAPAvailableForElement",
		"CIM_ManagedSystemElement",
		"LMI_MemberOfSoftwareCollection",
		"LMI_SoftwareInstallationServiceAffectsElement",
		"CIM_LogicalElement",
		"CIM_MemberOfCollection"]
	
	for clsnam in c.root.cimv2.classes():
		# Cet affichage car pour certaines classes, on bloque.
		# print "%70s : PRUDENCE" % ( clsnam )
		if clsnam in ["CIM_PCIController","CIM_SoftwareIdentity"]:
			print "%70s : TRES GROS MAIS CA MARCHE" % ( clsnam )
			continue
		
		# Hanging on "CIM_ServiceAffectsElement"
		if clsnam in hangingClasses:
			print "%70s : AIE OUIE" % ( clsnam )
			# ET POURTANT CA MARCHE, mais CMI_ServiceAffectsElement() est STUCK
			# c.root.cimv2.CMI_ServiceAffectsElement.instance_names()
			continue

		clsobj = getattr( c.root.cimv2, clsnam )
		#clsnames = clsobj.instance_names()
		#len_clsnames = len(clsnames)
		#if len_clsnames == 0:
		#	continue

		#print "%70s : %6d" % ( clsnam, len_clsnames )
		
		#clsobjs = clsobj.instances()
		#len_clsobjs = len(clsobjs)
		#if len_clsobjs != len_clsnames:
		#	print "Different lengths for objs:%d abd names:%d" % ( len_clsobjs, len_clsnames)
			
		print "Objects processing"
		for cimobj in clsobj.instances():
			print "Object=%s" % ( cimobj.path )
			# continue
			# Object=//Unknown-30-b5-c2-02-0c-b5-2.home/root/cimv2:LMI_SoftwareIdentityResource.CreationClassName="LMI_SoftwareIdentityResource",SystemName="Unknown-30-b5-c2-02-0c-b5-2.home",Name="fedora",SystemCreationClassName="PG_ComputerSystem"
			# Assocs nb=44763

			#clsassocs = cimobj.associator_names()
			#len_assocs = len(clsassocs)
			#print("Assocs nb=%d" % len_assocs )
			#if len_assocs != 0:
			#	print("Assocs=%s" % str(clsassocs) )
			#print("Assocs=%s" % str(clsassocs) )
			for assoc in cimobj.associator_names():
				sys.stdout.write( str(assoc) )
			sys.stdout.write("\n")
		print "End of objects processing"
	
	#procs = c.root.cimv2.Linux_UnixProcess.instances()
	#for p in procs:
	#	# print "{} {} {} {}".format(p.handle, p.ParentProcessID, p.Name, p.CreationDate)
	#	print "%6s %6s %s %s" % (p.handle, p.ParentProcessID, p.CreationDate, p.Name)

	print "End"



TestOPENLMI()