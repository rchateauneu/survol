import sys

# De facon generale, le user/pwd peut etre dans la ressource et donc la parser est dependant
# de la librairie, et donc eventuellement il faut charger une librairie et effectuer
# une fonction specifique. Autre cas, les URLs qui ont une facon standard de coder user/pass.
# En revanche, si le user/pass n est pas donne, on stocke de la meme facon.

credentials = {
	"Oracle": {
		"XE" : ( "system", "kennwert") # TODO: Eventuellement, la DB pourrait etre de la forme : scott/tiger@dbase ?
	},
	"WBEM" : {
		"http://127.0.0.1": ('', ''),
		"http://192.168.1.88": ('pegasus', 'toto'),
		"http://127.0.0.1": ('', ''),
		"192.168.1.78":   ('vero', 'wimereux62'), # Portable Windows 8
		"http://192.168.1.83:5988": ('', ''),
		"http://192.168.1.88:5988": ('pegasus', 'toto')
	},
	"Login" : { # SI C EST NOTRE MACHINE, RENVOYER ('','') Car pas besoin de impersonate ???
		"192.168.1.78":("rchateau", "kennwert"), # Titi Portable Windows8. win32 192.168.1.78 services:(5, 'OpenSCManager', 'Access is denied.')
		"192.168.1.83":("rchateau", "kennwert"),
		"rchateau-HP.home":("rchateau", "kennwert"),
		"rchateau-HP": ("rchateau", "kennwert")
	}
}

def GetCredentials( credType, credName ):
	try:
		arrType = credentials[credType]
		try:
			cred = arrType[credName]
			sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
			return cred
		except KeyError:
			sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
			return ('','')
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None
