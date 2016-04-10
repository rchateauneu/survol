import wmi
import win32com.client

# http://sawbuck.googlecode.com/svn/trunk/sawbuck/py/etw/generate_descriptor.py
# Generate symbols for the WbemScripting module so that we can have symbols
# for debugging and use constants throughout the file.
# Without this, win32com.client.constants is not available.
win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}',0, 1, 1)

# Essayer aussi wmi.ProvideConstants

# get the description from an WMI class using vbscript
# http://stackoverflow.com/questions/3978919/get-the-description-from-an-wmi-class-using-vbscript

# How Do I Display the Descriptions for WMI Class Properties Using Vbscript?
# http://stackoverflow.com/questions/22625818/how-do-i-display-the-descriptions-for-wmi-class-properties-using-vbscript?lq=1

wm = wmi.WMI()
pr = wm.Win32_Process

print("")

import pywintypes

def GetWmiClassDescriptionSlow(classNam):
	clsList = [ c for c in wm.SubclassesOf ("", win32com.client.constants.wbemFlagUseAmendedQualifiers) if classNam == c.Path_.Class ]
	theCls = clsList[0]
	try:
		return theCls.Qualifiers_("Description")
	except pywintypes.com_error:
		return ""

def GetWmiClassDescription(classNam):
	clsObj = getattr( wm, classNam )
	drv = clsObj.derivation()
	try:
		baseClass = drv[0]
	except IndexError:
		baseClass = ""
	try:
		clsList = [ c for c in wm.SubclassesOf (baseClass, win32com.client.constants.wbemFlagUseAmendedQualifiers) if classNam == c.Path_.Class ]
		theCls = clsList[0]
		return theCls.Qualifiers_("Description")
	except pywintypes.com_error:
		return ""


def GetWmiPropertiesDescription(connWmi, classNam):
	clsObj = getattr( connWmi, classNam )
	drv = clsObj.derivation()
	try:
		baseClass = drv[0]
	except IndexError:
		baseClass = ""
	try:
		clsList = [ c for c in wm.SubclassesOf (baseClass, win32com.client.constants.wbemFlagUseAmendedQualifiers) if classNam == c.Path_.Class ]
		theCls = clsList[0]

		for propObj in theCls.Properties_:
			propDsc = propObj.Qualifiers_("Description")
			yield ( propObj.Name, propDsc )

	except pywintypes.com_error:
		return



# On a teste avec un autrfe parametre qui est donc verifie.
#avant5 = [ c for c in wm.SubclassesOf ("", win32com.client.constants.wbemFlagUseAmendedQualifiers) if "Win32_Process" == c.Path_.Class ]
# for ca in avant5:
#	print(ca.Path_.Class)
#	print(ca.Qualifiers_("Description"))

allClasses = [ c.Path_.Class for c in wm.SubclassesOf ("", win32com.client.constants.wbemFlagUseAmendedQualifiers)  ]
# print(str(allClasses))


dscs = [ GetWmiClassDescription(c) for c in allClasses[:10]  ]

for s in dscs:
	if s:
		print(s)

print( GetWmiClassDescription("Win32_Process") )

for ( n,d) in GetWmiPropertiesDescription(wm,"Win32_Process"):
	print("%s=%s" % ( n,d))
#print(dir(avant5[0]))
#print(avant5[0].Qualifiers_)
#print(avant5[0].Path_.Class)
#print(avant5[0].Qualifiers_("Description"))

if False:
	print("")
	print("5 Path")
	print(avant5[0].Path_)
	print(dir(avant5[0].Path_))

#    return self._services.SubclassesOf(
#        category.Path_.Class,
#        win32com.client.constants.wbemFlagUseAmendedQualifiers)