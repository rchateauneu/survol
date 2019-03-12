# This tests the Windows WMI package, not the execution of a query.
import wmi
import sys
import time

def TstWatch(c, eventType):
	watcher = c.Win32_Process.watch_for(eventType)
	event = watcher()
	print(eventType + " occurred at", event.timestamp)

	print(event.path())
	prev = event.previous
	curr = event
	# Crashes a bit but not a problem
	for p in prev.properties:
		print(p)
		if prev is not None:
			pprev = getattr(prev, p)
			print("  Previous:", str(pprev))
		if curr is not None:
			pcurr = getattr(curr, p)
			print("   Current:", str(pcurr))


# http://timgolden.me.uk/python/wmi/tutorial.html
# http://timgolden.me.uk/python/wmi/cookbook.html

def PrintIt(cls, margin):
	sublst = c.subclasses_of(cls)
	cntsublst = len(sublst)
	total = 0
	if cntsublst != -1:
		print("%-60s:%20d" % (margin + cls, cntsublst))
		for i in sublst:
			total += PrintIt(str(i), margin + "    ")
	return cntsublst

def enumerate_namespaces(namespace=u"root", level=0):
	print level * "  ", namespace.split("/")[-1]
	c = wmi.WMI(namespace=namespace)
	for subnamespace in c.__NAMESPACE():
		enumerate_namespaces(namespace + "/" + subnamespace.Name, level + 1)

def EnuNa(Connect):
	print level * "  ", namespace.split("/")[-1]
	c = wmi.WMI(namespace=namespace)
	for subnamespace in c.__NAMESPACE():
		enumerate_namespaces(namespace + "/" + subnamespace.Name, level + 1)


# c = wmi.WMI("\\\\RCHATEAU-HP\\ROOT\\CIMV2")
# c = wmi.WMI(namespace=u"CIMV2")
# for ns in ["aspnet","Policy","HP"]:
# lstClasses = [x.Path_.Class for x in c.wmi.SubclassesOf()]

c = wmi.WMI(namespace="cimv2")
# lstClasses = [x.Path_.Class for x in c.wmi.SubclassesOf()]
# time.sleep(1)

dictClassToNode = dict()

def ClassToNode(clsNam):
	global dictClassToNode
	try:
		wmiNode = dictClassToNode[ clsNam ]
	except KeyError:
		wmiNode = clsNam + "_Pouet"
		dictClassToNode[ clsNam ] = wmiNode
	return wmiNode


# for cl in c.wmi.SubclassesOf():
#for cl in c.classes:
#	# PrintIt(cl,"")
#	# dir(cl)
#	st = cl
#	# print(st)
#
#	wmi_class = getattr (c, cl)
#	base_classes = wmi_class.derivation ()
#	print(str(base_classes))

rootNode = "tagada"

if 1 == 2:
	for clsNam in c.classes:
		wmiNode = ClassToNode(clsNam)
		wmi_class = getattr (c, clsNam)
		previousNode = wmiNode
		for baseClassNam in wmi_class.derivation ():
			wmiBaseNode = ClassToNode(baseClassNam)
			print(previousNode + " " + wmiBaseNode )
			previousNode = wmiBaseNode
		print(rootNode + " " + previousNode )


	# if st[0:13] == "Win32_Process":
	#	print( "OK:" + st + ":" + "cl.derivation" )
	# print(cl.Path_.Class + " " + cl.Path_.Class.derivation() )
	# PrintIt(cl,"")

# lst = c.Win32_Process()
# for l in lst:
#	print(str(l))


#drvlst = c.Win32_Process.derivation()
#print(drvlst)
# PrintIt("CIM_ManagedSystemElement", "")


# TstWatch(c,"modification")
# TstWatch(c,"creation")


# enumerate_namespaces()

# dir(c)
#for subnamespace in c.__NAMESPACE():
#	print(subnamespace)

# sys.stdin.read()

# Lister les instances.
#c.instances("Win32_Process")

# Creer un object a partir d un path et afficher ses proprietes avec differentiations si references.

#http://timgolden.me.uk/python/wmi/tutorial.html


def PrintPath(path):
	obj = wmi.WMI(moniker=path)

	print(obj)
	# print(str(obj))

	print("Keys")
	for prp in obj.keys:
		print(prp)
	print("")

	print("Properties")
	for prp in obj.properties:
		print( prp + " => " + str(getattr(obj,prp)) )
	print("")

	print("Associators")
	for prp in obj.associators():
		print(prp.path())
		#print(prp)
	print("")

	# Dont do this on a Win32_ComputerSystem object; it will take all day and kill your machine!
	print("References")
	for objRef in obj.references():
		print(objRef.path())
		for keyPrp in objRef.properties:
			# print( keyPrp + " => " + str(getattr(objRef,keyPrp)) )
			valPrp = getattr(objRef,keyPrp)
			try:
				# if valPrp.path() == path:
				if valPrp == obj:
					print( "   " + keyPrp + " >>> " + "IT IS ME" )
				else:
					print( "   " + keyPrp + " >>> " + str( valPrp.path() ) )
			except AttributeError:
				print( "   " + keyPrp + " >>> " + "NoStr:" + str(valPrp) )

		#print(prp)
		#print(prp.keys)
		#for k in prp:
		#	print("k="+k)
		#	print("v="+k)
	print("")


paths = (
	'\\\\RCHATEAU-HP\\root\\CIMV2:Win32_Process.Handle="7948"',
	'\\\\RCHATEAU-HP\\root\\CIMV2:Win32_DiskDrive.DeviceID="\\\\\\\\.\\\\PHYSICALDRIVE0"',
	'\\\\RCHATEAU-HP\\root\\CIMV2:Win32_NetworkAdapter.DeviceID="0"',
	'\\\\RCHATEAU-HP\\root\\cimv2:Win32_LogonSession.LogonId="999"'
)

for path in paths:
	print("===================================================================")
	PrintPath(path)