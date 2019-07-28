import os
import sys
import json
import socket
import lib_util
import lib_common
import lib_credentials
import lib_properties
from lib_properties import pc
import lib_kbase

try:
    import wmi
    import pywintypes
    import win32com.client

    # http://sawbuck.googlecode.com/svn/trunk/sawbuck/py/etw/generate_descriptor.py
    # Generate symbols for the WbemScripting module so that we can have symbols
    # for debugging and use constants throughout the file.
    # Without this, win32com.client.constants is not available.
    win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}',0, 1, 1)
    wmi_imported = True
except ImportError as exc:
    wmi_imported = False
    ERROR("Some modules could not be imported:%s",str(exc))

################################################################################
# TODO: Just a reminder that WMI can run on Linux, in a certain extent.
# https://pypi.python.org/pypi/wmi-client-wrapper

if False:

    if lib_util.isPlatformLinux:
        import wmi_client_wrapper as wmilnx

        wmic = wmilnx.WmiClientWrapper( username="Administrator", password="password", host="192.168.1.149", )

        output = wmic.query("SELECT * FROM Win32_Processor")

################################################################################

def BuildWmiMoniker( hostnameWmi, namespac = "", classNam = "" ):
    return "\\\\" + hostnameWmi + "\\" + namespac + ":" + classNam + "."

# namespaces_wmi.py
def WmiAllNamespacesUrl(hostnameWmi):
    wmiMoniker = BuildWmiMoniker( hostnameWmi )
    wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True, True, True )
    return wmiInstanceUrl

# objtypes_wmi.py. Beware: The class indicates the starting point for displaying the classes of the namespace.
def NamespaceUrl(nskey,hostnameWmi,classNam=""):
    wmiMoniker = BuildWmiMoniker( hostnameWmi, nskey, classNam )
    wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True, True )
    return wmiInstanceUrl

# class_wmi.py
def ClassUrl(nskey,hostnameWmi,classNam):
    wmiMoniker = BuildWmiMoniker( hostnameWmi, nskey, classNam )
    wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, True )
    return wmiInstanceUrl

################################################################################

def GetWmiUserPass(machWithBackSlashes):
    # WmiConnect cimom=\\\\rchateau-HP\\:. wmiNamspace=aspnet
    # cleanMachNam = machWithBackSlashes.replace("\\","").lower()
    cleanMachNam = machWithBackSlashes.replace("\\","")


    #sys.stderr.write("GetWmiUserPass cimom=%s cleanMachNam=%s\n" % ( machWithBackSlashes, cleanMachNam ) )

    wmiUserPass = lib_credentials.GetCredentials("WMI",cleanMachNam)

    #sys.stderr.write("GetWmiUserPass wmiUserPass=%s\n" % ( str(wmiUserPass) ) )

    if wmiUserPass[0]:
        return cleanMachNam, wmiUserPass[0], wmiUserPass[1]

    # WMI does not do local connection with the local IP.
    try:
        machIP = lib_util.GlobalGetHostByName(cleanMachNam)
    except:
        exc = sys.exc_info()[1]
        lib_common.ErrorMessageHtml("GetWmiUserPass: Cannot connect to WMI server:%s" % cleanMachNam)

    #sys.stderr.write("GetWmiUserPass machIP=%s\n" % ( machIP ) )

    wmiUserPass = lib_credentials.GetCredentials("WMI",machIP)
    return machIP, wmiUserPass[0], wmiUserPass[1]

# This works
# Before a given version, had to use server="xyz" instead of computer="xyz"
#c = wmi.WMI(computer="titi",user="titi\\rchateauneu@hotmail.com",password="my_hotmail_pass")
def WmiConnect(machWithBackSlashes,wmiNamspac,throw_if_error = True):
    # sys.stderr.write("WmiConnect cimom=%s wmiNamspace=%s\n" % ( machWithBackSlashes, wmiNamspac ) )
    # WmiConnect cimom=\\\\rchateau-HP\\:. wmiNamspace=aspnet


    if not machWithBackSlashes or lib_util.IsLocalAddress( machWithBackSlashes ):
        # sys.stderr.write("WmiConnect Local connect\n")
        # return wmi.WMI()
        return wmi.WMI(find_classes=False)

    wmiMachine, wmiUser, wmiPass = GetWmiUserPass(machWithBackSlashes)

    #wmiMachineIpAddr =  socket.gethostbyaddr(wmiMachine)
    #sys.stderr.write("WmiConnect wmiMachine=%s wmiMachineIpAddr=%s wmiUser=%s wmiPass=%s\n" % ( wmiMachine,wmiMachineIpAddr,wmiUser,wmiPass ) )

    dictParams = {}
    if wmiNamspac:
        dictParams['namespace'] = wmiNamspac

    if wmiUser:
        dictParams['user'] = wmiUser
        dictParams['password'] = wmiPass

    # TODO: THIS DOES NOT MAKE SENSE AND SHOULD BE CHANGED LIKE lib_wbem.py.
    if not lib_util.SameHostOrLocal( wmiMachine, None ):
        dictParams['computer'] = wmiMachine

    DEBUG("WmiConnect wmiMachine=%s wmiNamspac=%s dictParams=%s", wmiMachine, wmiNamspac, str(dictParams) )

    try:
        connWMI = wmi.WMI(**dictParams)
        #sys.stderr.write("WmiConnect after connection\n" )
    except:
        dictParams['password'] = "XXXYYYZZZ" # Security.
        if throw_if_error:
        # Could not connect, maybe the namespace is wrong.
            lib_common.ErrorMessageHtml("WmiConnect Cannot connect to WMI server with params:%s.Exc=%s" % (str(dictParams),str(sys.exc_info())))
        else:
            ERROR("WmiConnect Cannot connect to WMI server with params:%s.Exc=%s", str(dictParams),str(sys.exc_info()))
            return None

    #sys.stderr.write("WmiConnect returning\n" )
    return connWMI

################################################################################

# Returns the list of a keys of a given WBEM class. This is is used if the key is not given
# for an entity. This could be stored in a cache for better performance.
def WmiGetClassKeys( wmiNameSpace, wmiClass, cimomSrv ):
    DEBUG("WmiGetClassKeys wmiNameSpace=%s wmiClass=%s cimomSrv=%s", wmiNameSpace, wmiClass, cimomSrv )

    try:
        # TODO: Choose the namespace, remove "root\\" at the beginning.
        # wmi.WMI(namespace="aspnet")
        wmiCnnct = wmi.WMI(cimomSrv)
        wmiClass = getattr(wmiCnnct,wmiClass)
    except Exception:
        exc = sys.exc_info()[1]
        ERROR("WmiGetClassKeys %s %s %s: Caught:%s",cimomSrv, wmiNameSpace, wmiClass, str(exc) )
        return None

    wmiKeys = wmiClass.keys
    # sys.stderr.write("WmiGetClassKeys keys=%s\n" % ( str(wmiKeys) ) )
    return wmiKeys

# Normally we must find the right namespace, but default value is OK most of times.
def BuildWmiNamespaceClass( entity_namespace, entity_type ):
    # TODO: This is the default namespace where all "interesting" classes are.
    # At the moment, this is hard-coded because we have no interest into other namespaces.
    wmiNamespace = "root\\CIMV2"
    # Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
    return ( wmiNamespace, entity_type, wmiNamespace + ":" + entity_type )


def WmiBuildMonikerPath( entity_namespace, entity_type, entity_id ):
    wmiNameSpace, wmiClass, fullClassPth = BuildWmiNamespaceClass( entity_namespace, entity_type )

    # sys.stderr.write("WmiBuildMonikerPath wmiNameSpace=%s entity_namespace=%s entity_id=%s\n" % (wmiNameSpace, entity_namespace, str(entity_id)))

    return fullClassPth + "." + entity_id

def WmiInstanceUrl( entity_namespace, entity_type, entity_id, entity_host):
    # sys.stderr.write("WmiInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, entity_host))

    wmiFullPath = WmiBuildMonikerPath( entity_namespace, entity_type, entity_id )

    if wmiFullPath is None:
        return None

    # sys.stderr.write("WmiInstanceUrl wmiFullPath=%s\n" % (wmiFullPath))

    # 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
    wmiMoniker = "\\\\" + entity_host + "\\" + wmiFullPath
    wmiInstanceUrl = lib_util.EntityUrlFromMoniker( wmiMoniker, entity_id == "" )

    # sys.stderr.write("WmiInstanceUrl wmiInstanceUrl=%s\n" % (wmiInstanceUrl))
    return wmiInstanceUrl



################################################################################

def NormalHostName(entity_host):
    if entity_host == "":
        # Typically returns "RCHATEAU-HP".
        # Could also use platform.node() or socket.gethostname() or os.environ["COMPUTERNAME"]
        entity_host = socket.gethostname()
    return lib_util.EntHostToIp(entity_host)

################################################################################

# WMI from a Linux box
# http://www.tomsitpro.com/articles/issue-wmi-queries-from-linux,1-3436.html

# This returns a list of URLS.
def GetWmiUrl( entity_host, entity_namespace, entity_type, entity_id ):
    if not wmi_imported:
        return None

    entity_host = NormalHostName(entity_host)

    # sys.stderr.write("GetWmiUrl NormalHostName=%s ns=%s type=%s id=%s\n" % (entity_host, entity_namespace, entity_type, entity_id))

    # TODO: entity_host = NONE si current.

    if entity_type == "":
        # TODO: In fact this should rather display all classes for this namespace.
        wmiUrl = WmiAllNamespacesUrl( entity_host )
    else:
        wmiUrl = WmiInstanceUrl( entity_namespace, entity_type, entity_id, entity_host)

    # sys.stderr.write("GetWmiUrl %s %s %s %s wmiUrl=%s\n" % (entity_host, entity_namespace, entity_type, entity_id, wmiUrl))
    return wmiUrl

# These classes have too many members to be listed or even counted, let alone displayed.
def WmiTooManyInstances(className):
    # TODO: This list Should also include their base classes.
    # TODO: Have a mechanism to stop the process when it takes too long to return.
    return className in ['Win32_ComputerSystem','PG_ComputerSystem','CIM_UnitaryComputerSystem',
                         'CIM_ComputerSystem','CIM_System','CIM_LogicalElement','Win32_UserAccount',
                         'Win32_Group', 'CIM_ManagedSystemElement', 'CIM_Dependency', 'CIM_LogicalFile',
                         'CIM_SoftwareElement', 'CIM_Directory', 'CIM_DataFile' ]

def GetWmiClassFlagUseAmendedQualifiersn(connWmi, classNam):
    clsObj = getattr( connWmi, classNam )
    drv = clsObj.derivation()
    try:
        baseClass = drv[0]
    except IndexError:
        baseClass = ""
    return GetWmiClassFlagUseAmendedQualifiersAux(connWmi, classNam, baseClass)

# This stores the result of a costly operation.
dictBaseClassToSubClass = {}

def GetWmiClassFlagUseAmendedQualifiersAux(connWmi, classNam, baseClass):
    try:
        subclassesDict = dictBaseClassToSubClass[baseClass]
    except KeyError:
        try:
            subclasses = connWmi.SubclassesOf(baseClass, win32com.client.constants.wbemFlagUseAmendedQualifiers)
            subclassesDict = { c.Path_.Class : c for c in subclasses }
        except pywintypes.com_error:
            subclassesDict = {}
        dictBaseClassToSubClass[baseClass] = subclassesDict

    try:
        return subclassesDict[classNam]
    except KeyError:
        return None


# This returns the map of units for all properties of a class.
# https://msdn.microsoft.com/en-us/library/aa393650%28v=vs.85%29.aspx
#
# "All CIM-compliant implementations must handle a standard set of qualifiers.
# Units
# Data type: string
# Applies to: properties, methods, parameters
# Type of unit in which the associated data item is expressed. The default is NULL.
# For example, a size data item might have a value of "bytes" for Units."
#
#
# There are unit conversions which are specific to WMI.
# Example when displaying a Win32_Process:
# http://rchateau-hp:8000/survol/entity_wmi.py?xid=%5C%5CRCHATEAU-HP%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
#
# CSCreationClassName Win32_ComputerSystem
# KernelModeTime      407006609 100 nanoseconds
# OtherTransferCount  13745472 bytes
# PageFileUsage       56264 kilobytes
# PeakPageFileUsage   133264 kilobytes
# PeakVirtualSize     315052032 bytes
# PeakWorkingSetSize  116432 kilobytes
# ReadTransferCount   639502009 bytes
# UserModeTime        798881121 100 nanoseconds
# VirtualSize         235409408 bytes
# WorkingSetSize      15052800 bytes
# WriteTransferCount  13204197 bytes
#
# Some properties of the base class do not have an unit although they should.
# See CIM_Process, base class of Win32_Process:
# VirtualSize, PeakWorkingSetSize, PeakVirtualSize have no units.
# On the other hand WorkingSetSize is in "B" as expected.
#
# TODO: To fix this, for an object of type CIM_Process, use OSCreationClassName="Win32_OperatingSystem"
# That is: Use the units of the property of the actual class of the object, not its base class.
#
# Some units could be created:
# "PageFaults" : page / second
# "PageFileUsage" : Page
# "PeakPageFileUsage" : Page
#
def __WmiDictPropertiesUnitNoCache(connWmi, className):
    theCls = GetWmiClassFlagUseAmendedQualifiersn(connWmi, className)

    mapPropUnits = {}

    # Another approach
    #for qual in propObj.Qualifiers_:
    #    sys.stderr.write("        qual=%s => %s \n"%(qual.Name,qual.Value))
    for propObj in theCls.Properties_:
        try:
            # sys.stderr.write("    propObj.Qualifiers_('Description')=%s\n"%str(propObj.Qualifiers_("Description")))
            # sys.stderr.write("    propObj.Qualifiers_('Units')=%s\n"%str(propObj.Qualifiers_("Units")))
            propNam = propObj.Name # 'str(propObj.Qualifiers_("DisplayName"))'
            unitNam = str(propObj.Qualifiers_("Units"))
            mapPropUnits[propNam] = unitNam
            # sys.stderr.write("WmiDictPropertiesUnit propNam=%s unitNam=%s\n"%(propNam,unitNam))

        # except pywintypes.com_error:
        except :
            exc = sys.exc_info()[1]
            #sys.stderr.write("WmiDictPropertiesUnit propNam=%s caught:%s \n"%(propNam,str(exc)))

    return mapPropUnits

# So, this is calculated only once per class, because it does not change,
# and does not depend on the connection, because it is a WMI data.
__cacheWmiDictPropertiesUnit = {}

def WmiDictPropertiesUnit(connWmi, className):
    try:
        mapPropUnits = __cacheWmiDictPropertiesUnit[className]
    except KeyError:
        mapPropUnits = __WmiDictPropertiesUnitNoCache(connWmi, className)
        __cacheWmiDictPropertiesUnit[className] = mapPropUnits
    return mapPropUnits


def WmiAddClassQualifiers( grph, connWmi, wmiClassNode, className, withProps ):
    """This adds information to a WMI class."""
    try:
        # No need to print this, at the moment.
        if False:
            klassDescr = str( dir( getattr( connWmi, className ) ) )
            grph.add( ( wmiClassNode, lib_common.MakeProp("dir"), lib_common.NodeLiteral(klassDescr) ) )

            klassDescr = str( getattr( connWmi, className )._properties )
            grph.add( ( wmiClassNode, lib_common.MakeProp("_properties"), lib_common.NodeLiteral(klassDescr) ) )

            klassDescr = str( getattr( connWmi, className ).properties["Description"] )
            grph.add( ( wmiClassNode, lib_common.MakeProp("properties.Description"), lib_common.NodeLiteral(klassDescr) ) )

            klassDescr = str( getattr( connWmi, className ).property_map )
            # Otherwise it crashes.
            # klassDescrClean = klassDescr.replace("{"," ").replace("}"," ")
            # sys.stderr.write("klassDescr=%s\n"%klassDescr)
            grph.add( ( wmiClassNode, lib_common.MakeProp("property_map"), lib_common.NodeLiteral(klassDescr.replace("{"," ").replace("}"," ") ) ) )


        theCls = GetWmiClassFlagUseAmendedQualifiersn(connWmi, className)
        if theCls:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/wmi-class-qualifiers
            # Specifies a description of the block for the locale specified by the Locale qualifier.
            # If defined, WMI clients can display the description string to users.
            klassDescr = theCls.Qualifiers_("Description")
            # Beware, klassDescr is of type "instance".
            strKlassDescr = lib_util.six_text_type(klassDescr)

            # This might be a value with broken HTML tags such as:
            # "CIM_DataFile is a type ... <B>The behavior ... e returned.<B>"
            strKlassDescr = strKlassDescr.replace("<B>","")

            grph.add( ( wmiClassNode, pc.property_information, lib_common.NodeLiteral(strKlassDescr) ) )

            if withProps:
                for propObj in theCls.Properties_:
                    propDsc = lib_util.six_text_type(propObj.Qualifiers_("Description"))

                    # Properties of different origins should not be mixed.
                    # Prefixes the property with a dot, so sorting displays it at the end.
                    # Surprisingly, the dot becomes invisible.
                    grph.add( ( wmiClassNode, lib_common.MakeProp("."+propObj.Name), lib_common.NodeLiteral(propDsc) ) )
        else:
            grph.add( ( wmiClassNode, pc.property_information, lib_common.NodeLiteral("No description available for %s" % className) ) )

        klassQuals = getattr( connWmi, className ).qualifiers
        for klaQualKey in klassQuals :
            klaQualVal = klassQuals[klaQualKey]
            # sys.stderr.write("WmiAddClassQualifiers klaQualVal=%s / %s\n"%(str(klaQualVal),str(type(klaQualVal))))
            if isinstance(klaQualVal,tuple):
                klaQualVal = "{ " + ",".join(klaQualVal) + " }"

            # Some specific properties match an entity class, so we can create a node.
            # IT WORKS BUT IT IS NOT NICE AS IT IS A SEPARATE NODE.
            # We would like to have a clickable URL displayed in a table TD.
            if klaQualKey == "UUID":
                nodeUUID = lib_common.gUriGen.ComTypeLibUri( klaQualVal )
                grph.add( ( wmiClassNode, lib_common.MakeProp(klaQualKey), nodeUUID ) )
                continue

            grph.add( ( wmiClassNode, lib_common.MakeProp(klaQualKey), lib_common.NodeLiteral(klaQualVal) ) )
    except Exception:
        exc = sys.exc_info()[1]
        try:
            # Dumped in json so that lists can be appropriately deserialized then displayed.
            errStr = json.dumps(list(exc))
        except:
            # Might have caught: 'com_error' object is not iterable
            errStr = json.dumps("Non-iterable COM Error:"+str(exc))
        grph.add( ( wmiClassNode, lib_common.MakeProp("WMI Error"), lib_common.NodeLiteral(errStr) ) )

# Tells if this class for our ontology is in a given WMI server, whatever the namespace is.
# This is used to display or not, the WMI url associated to a Survol object.
def ValidClassWmi(className):
    tpSplit = className.split("_")
    tpPrefix = tpSplit[0]
    return tpPrefix in ["CIM","Win32","WMI"]


def WmiAddClassNode(grph,connWmi,wmiNode,entity_host, nameSpace, className, prop):
        wmiurl = GetWmiUrl( entity_host, nameSpace, className, "" )
        if wmiurl is None:
            return

        wmiClassNode = lib_common.NodeUrl(wmiurl)

        grph.add( ( wmiClassNode, prop, wmiNode ) )

        WmiAddClassQualifiers( grph, connWmi, wmiClassNode, className, False )
        return wmiClassNode

def WmiBaseClasses(connWmi, className):
    """
        This returns the base classes of a WMI class.
    """
    # Adds the qualifiers of this class.
    klassObj = getattr( connWmi, className )

    # It always work even if there is no object.
    return klassObj.derivation()

# Adds the list of base classes. Returns the list of pairs (name node),
# so it can be matched againt another inheritance tree.
def WmiAddBaseClasses(grph,connWmi,wmiNode,entity_host, nameSpace, className):
    pairsNameNode = dict()

    wmiSubNode = wmiNode

    # It always work even if there is no object.
    for baseKlass in WmiBaseClasses( connWmi, className ):
        wmiClassNode = WmiAddClassNode(grph,connWmi,wmiSubNode,entity_host, nameSpace, baseKlass, pc.property_cim_subclass)
        pairsNameNode[baseKlass] = wmiClassNode
        wmiSubNode = wmiClassNode
    return pairsNameNode

# This must return the label of an url "entity_wmi.py".
# For example, the name of a process when the PID (Handle) is given.
# Due to performance problems, consider using a cache.
# Or a default value for some "expensive" classes.
def EntityToLabelWmi(namSpac, entity_type_NoNS, entity_id, entity_host):
    # sys.stderr.write("EntityToLabelWmi\n")
    return None

# Survol contains three different ontologies: The ontology of classes defined by Survol,
# and the ontology of WMI and WBEM classes respectively. These three ontologies
# share many different classes and, most importantly, do not contradict.
# For example: The same class defined in two different ontologies might have partly
# different attributes, but the common ones have the same meaning and usage.
# The reason for having three ontologies are:
# - WMI on Windows and OpenLMI (OpenPegasus) on Linux, follow the WBEM standard,
#   and define the most import classes in a computer system.
# - But WBEM standard has limitations:
#   = WQL queries can be very very slow, and tend to return only objects of the same type.
#   = It is not possible define new classes (by creating providers) in a portable manner.
#   = WQL has limitations.
#
# On the other hand:
# - Creating a new class takes a couple of Python lines.
# - A script can return any combinations of objects types.
#
# In the three cases, Survol, WMI and WBEM, ontologies are implemented with a dictionary.
# TODO: How to display the information of associators and references ?
def ExtractWmiOntology():
    cnn = wmi.WMI()

    map_classes = {}
    map_attributes = {}

    for class_name in cnn.classes:
        cls_obj = getattr(cnn, class_name)

        drv_list = cls_obj.derivation()
        # If this is a top-level class, the derivation list is empty.
        # Otherwise, it is the list of base classes names going to the top.
        if drv_list:
            base_class_name = drv_list[0]
        else:
            base_class_name = ""

        theCls = GetWmiClassFlagUseAmendedQualifiersAux(cnn, class_name, base_class_name)
        text_descr = ""
        if theCls:
            try:
                textDsc = theCls.Qualifiers_("Description")
                text_descr = lib_util.six_text_type(textDsc)
                # pywintypes.com_error: (-2147352567, 'Exception occurred.', (0, u'SWbemQualifierSet', u'Not found ', None, 0, -2147217406), None)
            except pywintypes.com_error:
                pass

        map_classes[class_name] = {"base_class": base_class_name, "class_description": text_descr}

        for p in cls_obj.properties:
            prop_obj = cls_obj.wmi_property(p)
            try:
                map_attributes[prop_obj.name]["predicate_type"]
                continue
            except KeyError:
                pass

            try:
                only_read = prop_obj.qualifiers['read']
            except:
                only_read = False
            if not only_read:
                map_attributes[prop_obj.name] = {
                    "predicate_type": prop_obj.type,
                    "predicate_domain": class_name }

        # Second enumeration of properties, different style.
        if theCls:
            for propObj in theCls.Properties_:
                try:
                    map_attributes[propObj.Name]["predicate_description"]
                    continue
                except KeyError:
                    pass
                try:
                    # UnicodeEncodeError: 'ascii' codec can't encode character u'\xa0' in position 178: ordinal not in range(128)
                    propDsc = propObj.Qualifiers_("Description")
                    propTxt = lib_util.six_text_type(propDsc)
                    map_attributes.get(propObj.Name,{})["predicate_description"] = propTxt
                except pywintypes.com_error:
                    # pywintypes.com_error: (-2147352567, 'Exception occurred.', (0, u'SWbemQualifierSet', u'Not found ', None, 0, -2147217406), None)
                    pass

    return map_classes, map_attributes

################################################################################

# Add all usual Python types.
scalarDataTypes = lib_util.six_string_types + ( lib_util.six_text_type, lib_util.six_binary_type ) + lib_util.six_integer_types

# This is a hard-coded list of properties which cannot be displayed.
# They should be stored in the class directory. This is a temporary hack
# until we find a general rule, or find similar properties.
# TODO: Convert this into an image. Find similar properties.
# At least display the type when it happens.
prpCannotBeDisplayed = {
    "CIM_ComputerSystem" : ["OEMLogoBitmap"]
}

# There are unit conversions which are specific to WMI.
# Example when displaying a Win32_Process:
# http://rchateau-hp:8000/survol/entity_wmi.py?xid=%5C%5CRCHATEAU-HP%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
#
# CSCreationClassName Win32_ComputerSystem
# KernelModeTime      407006609 100 nanoseconds
# OtherTransferCount  13745472 bytes
# PageFileUsage       56264 kilobytes
# PeakPageFileUsage   133264 kilobytes
# PeakVirtualSize     315052032 bytes
# PeakWorkingSetSize  116432 kilobytes
# ReadTransferCount   639502009 bytes
# UserModeTime        798881121 100 nanoseconds
# VirtualSize         235409408 bytes
# WorkingSetSize      15052800 bytes
# WriteTransferCount  13204197 bytes
def UnitConversion(aFltValue, valUnit):
    try:
        unitNotation = {
            "bytes" : "B",
            "kilobytes" : "kB"
        }[valUnit]
        return lib_util.AddSIUnit( aFltValue, unitNotation )
    except KeyError:
        pass

    # Special case needing a conversion. Jeefie.
    if valUnit == "100 nanoseconds":
        return lib_util.AddSIUnit( float(aFltValue) / 10, "ms" )

    # Unknown unit.
    return lib_util.AddSIUnit( aFltValue, valUnit )


def WmiKeyValues(connWmi, objWmi, displayNoneValues, className ):
    """
        Returns the properties and values of a WMI object (Not a class).
    """

    # This returns the map of units for all properties of a class.
    # Consider using the value of the property "OSCreationClassName",
    # because units properties of base classes are not always documented.
    mapPropUnits = WmiDictPropertiesUnit(connWmi, className)

    for prpName in objWmi.properties:

        # Some common properties are not displayed because the value is cumbersome,
        # and do not bring useful information.
        if prpName in ["OSName"]:
            continue

        prpProp = lib_common.MakeProp(prpName)

        try:
            valUnit = mapPropUnits[prpName]
        except KeyError:
            valUnit = ""

        # className="CIM_ComputerSystem" for example.
        try:
            doNotDisplay = prpName in prpCannotBeDisplayed[className]
        except KeyError:
            doNotDisplay = False

        if doNotDisplay:
            WARNING("Cannot display:%s",str(getattr(objWmi, prpName)))
            value = "Cannot be displayed"
        else:
            # BEWARE, it could be None.
            value = getattr(objWmi, prpName)

        # Date format: "20189987698769876.97987+000", Universal Time Coordinate (UTC)
        # yyyymmddHHMMSS.xxxxxx +- UUU
        # yyyy represents the year.
        # mm represents the month.
        # dd represents the day.
        # HH represents the hour (in 24-hour format).
        # MM represents the minutes.
        # SS represents the seconds.
        # xxxxxx represents the milliseconds.
        # UUU represents the difference, in minutes, between the local time zone and Greenwich Mean Time (GMT).
        if prpName in ["CreationDate"]:
            try:
                dtYear = value[0:4]
                dtMonth = value[4:6]
                dtDay = value[6:8]
                dtHour = value[8:10]
                dtMinute = value[10:12]
                dtSecond = value[12:14]

                value = "%s-%s-%s %s:%s:%s" % (dtYear,dtMonth,dtDay,dtHour,dtMinute,dtSecond)
            except:
                pass

        # The "GUID" property is very specific in WMI.
        if prpName == "GUID":
            # Example: "{CF185B35-1F88-46CF-A6CE-BDECFBB59B4F}"
            nodeGUID = lib_common.gUriGen.ComTypeLibUri( value )
            yield( prpProp, nodeGUID )
            continue

        if isinstance( value, scalarDataTypes ):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            valueReplaced = str(value).replace('\\','\\\\')

            if valUnit:
                valueReplaced = UnitConversion( valueReplaced, valUnit )
            yield ( prpProp, lib_common.NodeLiteral( valueReplaced ) )
        elif isinstance( value, ( tuple) ):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            tupleReplaced = [ str(oneVal).replace('\\','\\\\') for oneVal in value ]

            # tuples are displayed as tokens separated by ";". Examples:
            #
            # CIM_ComputerSystem.OEMStringArray
            #" ABS 70/71 60 61 62 63; ;FBYTE#2U3E3X47676J6S6b727H7M7Q7T7W7m8D949RaBagapaqb3bmced3.fH;; BUILDID#13WWHCHW602#SABU#DABU;"
            #
            # CIM_ComputerSystem.Roles
            # "LM_Workstation ; LM_Server ; SQLServer ; NT ; Potential_Browser ; Master_Browser"
            cleanTuple = " ; ".join( tupleReplaced )
            yield( prpProp, lib_common.NodeLiteral( cleanTuple ) )
        elif value is None:
            if displayNoneValues:
                yield( prpProp, lib_common.NodeLiteral( "None" ) )
        else:
            try:
                refMoniker = str( value.path() )
                refInstanceUrl = lib_util.EntityUrlFromMoniker( refMoniker )
                refInstanceNode = lib_common.NodeUrl(refInstanceUrl)
                yield( prpProp, refInstanceNode )
            except AttributeError:
                exc = sys.exc_info()[1]
                yield( prpProp, lib_common.NodeLiteral( str(exc) ) )

class WmiSparqlCallbackApi:
    def __init__(self):
        # Current host and default namespace.
        self.m_wmi_connection = WmiConnect("","")

    def CallbackSelect(self, grph, class_name, predicate_prefix, filtered_where_key_values):
        WARNING("WmiCallbackSelect class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
        assert class_name

        # This comes from such a Sparql triple: " ?variable rdf:type rdf:type"
        if class_name == "type":
            return

        # HACK: Temporary hard-code !!
        if class_name == "CIM_DataFile" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/","\\")
            WARNING("WmiCallbackSelect REPLACED CIM_DataFile where_key_values=%s", filtered_where_key_values)
        elif class_name == "CIM_Directory" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/","\\")
            WARNING("WmiCallbackSelect REPLACED CIM_Directory where_key_values=%s", filtered_where_key_values)

        wmi_query = lib_util.SplitMonikToWQL(filtered_where_key_values,class_name)
        WARNING("WmiCallbackSelect wmi_query=%s", wmi_query)

        wmi_objects = self.m_wmi_connection.query(wmi_query)

        for one_wmi_object in wmi_objects:
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            WARNING("one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name )
            dict_key_values = { node_key: node_value for node_key, node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral("WMI")

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            WARNING("dict_key_values=%s",dict_key_values)
            #object_path_node = lib_util.NodeUrl(object_path)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield ( object_path, dict_key_values )


    # This returns a data structure similar to WmiCallbackSelect
    def CallbackAssociator(
        self,
        grph,
        result_class_name,
        predicate_prefix,
        associator_key_name,
        wmi_path_full):
        # subject_path_node as previously returned by WmiCallbackSelect
        WARNING("WmiCallbackAssociator wmi_path_full=%s result_class_name=%s associator_key_name=%s",
                wmi_path_full,
                result_class_name,
                associator_key_name)
        assert wmi_path_full

        # wmi_path = '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="31588"'
        # wmi_path_full = str(subject_path_node)
        # wmi_path_full = subject_path
        dummy, colon, wmi_path = wmi_path_full.partition(":")
        WARNING("WmiCallbackAssociator wmi_path=%s", wmi_path)

        # HACK: Temporary hard-code !! Same problem as WmiCallbackSelect
        # TODO: We must quadruple backslashes in Sparql queries.
        if "CIM_DataFile.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\","\\")
            WARNING("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "CIM_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            WARNING("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "Win32_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\","\\")
            WARNING("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        assert wmi_path

        # 'ASSOCIATORS OF {Win32_Process.Handle="1780"} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile'
        # 'ASSOCIATORS OF {CIM_DataFile.Name="c:\\program files\\mozilla firefox\\firefox.exe"} WHERE AssocClass = CIM_ProcessExecutable ResultClass = CIM_Process'
        wmi_query = "ASSOCIATORS OF {%s} WHERE AssocClass=%s ResultClass=%s" % (wmi_path, associator_key_name, result_class_name)

        WARNING("WmiCallbackAssociator wmi_query=%s", wmi_query)

        wmi_objects = self.m_wmi_connection.query(wmi_query)

        for one_wmi_object in wmi_objects:
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            DEBUG("WmiCallbackAssociator one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, result_class_name )
            dict_key_values = { node_key:node_value for node_key,node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral("WMI")

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"
            # p=http://www.w3.org/1999/02/22-rdf-syntax-ns#type
            # o=http://primhillcomputers.com/survol/Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeNodeForSparql(result_class_name)

            DEBUG("WmiCallbackAssociator dict_key_values=%s",dict_key_values)
            #object_path_node = lib_util.NodeUrl(object_path)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield ( object_path, dict_key_values )

    # This returns the available types
    def CallbackTypes(self, grph, see_also):
        WARNING("CallbackTypes")
        for one_class_name in self.m_wmi_connection.classes:
            yield "WmiClass:" + one_class_name, { "Name":one_class_name}

