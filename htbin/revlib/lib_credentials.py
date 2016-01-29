

# De facon generale, le user/pwd peut etre dans la ressource et donc la parser est dependant
# de la librairie, et donc eventuellement il faut charger une librairie et effectuer
# une fonction specifique. Autre cas, les URLs qui ont une facon standard de coder user/pass.
# En revanche, si le user/pass n est pas donne, on stocke de la meme facon.
def GetCredentials( credType, credName ):
	if credType == "Oracle":
		# TODO: Eventuellement, la DB pourrait etre de la forme : scott/tiger@dbase ?
		if credName == "XE":
			return ( "system", "xxxxx")
	elif credType == "WBEM":
		if credName == "http://127.0.0.1":
			return ('', '')
		if credName == "http://192.168.1.88":
			return ('pegasus', 'toto')
		# TODO: Mettre ca au propre !!!!!!!!!!!!!!
		if credName == "http://127.0.0.1":
			return ('', '')
		if credName == "192.168.1.78":   # Portable Windows 8
			return ('vero', 'xxxxx')
		if credName == "http://192.168.1.83:5988":
			return ('', '')
		if credName == "http://192.168.1.88:5988":
			return ('pegasus', 'toto')
		return ('', '')
	elif credType == "Login":
		# SI C EST NOTRE MACHINE, RENVOYER ('','') Car pas beson de impersonate ???


		if credName == "192.168.1.78":
			# win32 192.168.1.78 services:(5, 'OpenSCManager', 'Access is denied.')
			return ("rchateau", "xxxxx")
		if credName in ( "192.168.1.83", "rchateau-HP.home", "rchateau-HP" ):
			return ("rchateau", "xxxxx")
		return ('', '')

	return None