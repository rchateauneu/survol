import pywbem
import pywbem.cim_provider2

# http://blog.fpmurphy.com/2013/06/openlmi-open-linux-management-interface.html

def TestEnuma():
	conn = pywbem.WBEMConnection("http://192.168.1.88", ("pegasus", "toto"))
	for cla_name in conn.EnumerateClassNames():
		asso = conn.Associators(cla_name)
		if len(asso) > 0 :
			print "Class=%s len associators=%d" % ( cla_name, len(asso) )
			
			# cla_obj = conn.GetClass(cla_name)
			# Cannot import name CryptoError
			try:
				cla_insts_nam = conn.EnumerateInstanceNames(cla_name)
				print "Instances names len=" % len(cla_insts_nam)
				cla_insts = conn.EnumerateInstances(cla_name)
				print "Instances len=" % len(cla_insts)
			except Exception as ex:
				print "Caught:%s" % ( str(ex) )
				
			asso_names = conn.AssociatorNames(cla_name)
			print "Assocs=%s" % len(asso_names)
			for asso_nm in asso_names:
				print "    %s" % asso_nm
				
			
			print ""

def TestPYWBEM():

	conn = pywbem.WBEMConnection("http://192.168.1.88", ("pegasus", "toto"))

	with_code = False
	if  with_code:
		cl = conn.GetClass("LMI_ServiceAffectsIdentity")
		(provider, registration) = pywbem.cim_provider2.codegen(cl)

		print provider
		print registration
		
	svc = conn.EnumerateInstances("LMI_ServiceAffectsIdentity")

	print svc[0]
	# print svc[0].instance.items()

TestEnuma()
if False:
	TestPYWBEM()
