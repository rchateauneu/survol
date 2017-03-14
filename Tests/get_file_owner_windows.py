
FILENAME = "C:\\Program Files (x86)\\NETGEAR\\WNDA3100v3\\WNDA3100v3.EXE"


def WindowsAddFileOwner(filNam):
	import win32api
	import win32con
	import win32security

	def SID_CodeToName(typeSID):
		mapSIDList = {
			win32security.SidTypeUser: "User SID",
			win32security.SidTypeGroup: "Group SID",
			win32security.SidTypeDomain: "Domain SID",
			win32security.SidTypeAlias: "Alias SID",
			win32security.SidTypeWellKnownGroup: "Well-known group",
			win32security.SidTypeDeletedAccount: "Deleted account",
			win32security.SidTypeInvalid: "Invalid SID",
			win32security.SidTypeUnknown: "Unknown type SID",
			win32security.SidTypeComputer: "Computer SID",
			# win32security.SidTypeLabel: "Mandatory integrity label SID" # NOT DEFINED
		}

		try:
			return mapSIDList[typeSID]
		except:
			return "Unknown SID"

	try:
		open (filNam, "r").close ()

		#print "I am", win32api.GetUserNameEx (win32con.NameSamCompatible)

		sd = win32security.GetFileSecurity (filNam, win32security.OWNER_SECURITY_INFORMATION)
		owner_sid = sd.GetSecurityDescriptorOwner ()
		name, domain, type = win32security.LookupAccountSid (None, owner_sid)
		typNam = SID_CodeToName(type)
		print "Domain=%s Name=%s Type=%s " % (domain, name,typNam)


		win32security.SidTypeWellKnownGroup
	except:
		print("EXception")
		return None

WindowsAddFileOwner(FILENAME)
