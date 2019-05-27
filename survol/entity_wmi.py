#!/usr/bin/python

"""
WMI instance
"""

import sys
import time
import lib_common
import lib_wmi
import lib_util

try:
    import wmi
except ImportError:
    lib_common.ErrorMessageHtml("WMI Python library not installed")

# Do not use WQL because it filters data after they have been selected by WMI.
# On the contrary, WMI applies its filters on classes.
# A WMI Filter is a set of conditions used against the instances of a WMI Class
# which defines whether or not an instance should be reported or excluded.
def WmiReadWithMoniker( cgiEnv, cgiMoniker ):
    """
        This returns an array of the single object read wrom WMI with the moniker.
        Or null if no such object exists.
    """
    try:
        objWmi = wmi.WMI(moniker=cgiMoniker,find_classes=False)
        return [ objWmi ]
    except Exception:
        exc = sys.exc_info()[1]
        DEBUG("cgiMoniker=%s Caught:%s", cgiMoniker, str(exc) )
        return None

def WmiReadWithQuery( cgiEnv, connWmi, className ):
    """
        Maybe reading with the moniker does not work because not all properties.
        This splits the moniker into key value paris, and uses a WQL query.
    """
    splitMonik = lib_util.SplitMoniker( cgiEnv.m_entity_id )
    aQry = lib_util.SplitMonikToWQL(splitMonik,className)

    try:
        return connWmi.query(aQry)
    except Exception:
        exc = sys.exc_info()[1]
        lib_common.ErrorMessageHtml("Query=%s Caught:%s" % ( aQry, str(exc) ) )


def DispWmiProperties(grph, connWmi, wmiInstanceNode, objWmi, displayNoneValues, className ):
    """
        Get the properties and values of a WMI object (Not a class),
        then adds them to the triples graph.
    """

    lstKeyValues = lib_wmi.WmiKeyValues(connWmi, objWmi, displayNoneValues, className )
    for prpProp, prpValue in lstKeyValues:
        grph.add( ( wmiInstanceNode, prpProp, prpValue ) )


def ImportSurvolModuleFromWmiClass(connWmi, className):
    allBaseClasses = ( className, ) + lib_wmi.WmiBaseClasses(connWmi, className)
    for theClassAscending in allBaseClasses:
        # Maybe there is a module without ontology.
        # In this case, try a base class. This is what does this function.
        ontoKeys = lib_util.OntologyClassKeys(theClassAscending)
        if len(ontoKeys):
            return ( theClassAscending, ontoKeys )
    return None,None

def AddSurvolObjectFromWmi(grph,wmiInstanceNode,connWmi,className,objList):
    """
        Must find the url of the object in the Survol terminoloy equivalent to this one in WMI.
        This does not care the namespace which is set to root/cimv2 anyway.
        The reason is that it is the most common one, and the others seem to be used
        for very technical purpose.
    """

    # The first step is to iterate on the base classes until there is one of the Survol classes.
    ( survolEquivalentClass, ontoKeys ) = ImportSurvolModuleFromWmiClass(connWmi, className)

    # This class nor any of its base classes exists in Survol.
    if survolEquivalentClass is None:
        return

    setSurvolUrls = set()

    for objWmi in objList:
        # sys.stderr.write("objWmi=[%s]\n" % str(objWmi) )

        propValuesArray = []

        # For each property of the survol ontology, picks the value returned by WMI.
        # Replace missing values by an empty string.
        for survKey in ontoKeys:
            try:
                wmiVal = getattr(objWmi,survKey)
            except KeyError:
                INFO("AddSurvolObjectFromWmi className=%s no value for key=%s",className,survKey)
                wmiVal = ""
            propValuesArray.append(wmiVal)

        entityModule = lib_util.GetEntityModule(survolEquivalentClass)

        # Maybe there is a special function for encoding these arguments.
        try:
            urlSurvol = entityModule.MakeUri(*propValuesArray)
        except:
            # Otherwise, general case.
            urlSurvol = lib_common.gUriGen.UriMake(survolEquivalentClass,*propValuesArray)

        setSurvolUrls.add(urlSurvol)

    # There might potentially be several Survol objects for these several WMI objects.
    # It depends on the properties, as Survol takes only a subset of them.
    # Prefixed by hyphens so that it comes first when sorted.
    propWmi2Survol = lib_common.MakeProp("--Survol equivalent object")
    for urlSurvol in setSurvolUrls:
        grph.add( ( wmiInstanceNode, propWmi2Survol, urlSurvol ) )
    return


# Better use references() because it gives much more information.
#for assoc in objWmi.associators():
#    assocMoniker = str( assoc.path() )
#    sys.stderr.write("assocMoniker=[%s]\n" % assocMoniker )
#    assocInstanceUrl = lib_util.EntityUrlFromMoniker( assocMoniker )
#    assocInstanceNode = lib_common.NodeUrl(assocInstanceUrl)
#    grph.add( ( wmiInstanceNode, lib_common.MakeProp("assoc"), assocInstanceNode ) )

# TESTS:
# OK
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="rchateau-hp"')
# _wmi_object: \\RCHATEAU-HP\root\CIMV2:Win32_ComputerSystem.Name="rchateau-hp">
# KAPUTT
# wmi.WMI(moniker='\\rchateau-HP\root\CIMV2:CIM_ComputerSystem.Name="rchateau-hp"')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name=rchateau-hp')
# wmi.WMI(moniker='root\CIMV2:CIM_ComputerSystem.Name="127.0.0.1"')



# All instances that are associated with a particular source instance.
def DisplayObjectAssociators(grph,wmiInstanceNode,objWmi,cgiMoniker):
    DEBUG("DisplayObjectAssociators\n")
    # It is possible to restrict the associators to a specific class only.
    for anAssoc in objWmi.associators():
        # assocMoniker=\\RCHATEAU-HP\root\cimv2:Win32_ComputerSystem.Name="RCHATEAU-HP"
        assocMoniker = str(anAssoc.path())
        DEBUG("DisplayObjectAssociators anAssoc Moniker=%s",assocMoniker)

        # derivation=(u'CIM_UnitaryComputerSystem', u'CIM_ComputerSystem', u'CIM_System', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
        assocDerivation = anAssoc.derivation()

        DEBUG("DisplayObjectAssociators anAssoc derivation=%s",str(assocDerivation))
        # sys.stderr.write("DisplayObjectAssociators anAssoc=%s\n"%str(dir(anAssoc)))

        # TODO: Consider these methods: associated_classes, associators, derivation,
        # id, keys, methods, ole_object, path, properties, property_map, put,
        # qualifiers, references, set, wmi_property

        # BEWARE: For example for CIM_ComputerSystem, the host name must be in lowercase.
        # TODO: This is not done here. Luckily the universal alias does this properly.
        assocInstanceUrl = lib_util.EntityUrlFromMoniker( assocMoniker )
        assocInstanceNode = lib_common.NodeUrl(assocInstanceUrl)
        grph.add( ( wmiInstanceNode, lib_common.MakeProp(assocDerivation[0]), assocInstanceNode ) )




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


# The references() retrieves all association instances that refer to a particular source instance.
# It is similar to the associators()statement.
# However, rather than retrieving endpoint instances, it retrieves the intervening association instances.
# Dont do this on a Win32_ComputerSystem object and several other classes; it is VERY SLOW !
# TODO: Test with a small data set.
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
                    refInstanceNode = lib_common.NodeUrl(refInstanceUrl)
                    grph.add( ( wmiInstanceNode, lib_common.MakeProp(keyPrp), refInstanceNode ) )
            except AttributeError:
                # Then it is a literal attribute.
                # TODO: Maybe we could test if the type is an instance.
                # Beware: UnicodeEncodeError: 'ascii' codec can't encode character u'\\u2013'
                try:
                    literalKeyValue[ keyPrp ] = str(valPrp)
                except UnicodeEncodeError:
                    literalKeyValue[ keyPrp ] = "UnicodeEncodeError"


        # Now the literal properties are attached to the other node.
        if refInstanceNode != None:
            for keyLitt in literalKeyValue:
                grph.add( ( refInstanceNode, lib_common.MakeProp(keyLitt), lib_common.NodeLiteral( literalKeyValue[ keyLitt ] ) ) )

def Main():
    paramkeyDisplayNone = "Display none values"
    paramkeyDisplayAssociators = "Display Associators"
    cgiEnv = lib_common.CgiEnv(can_process_remote=True,
                                    parameters = { paramkeyDisplayNone : False, paramkeyDisplayAssociators : False })

    displayNoneValues = bool(cgiEnv.GetParameters( paramkeyDisplayNone ))
    displayAssociators = bool(cgiEnv.GetParameters( paramkeyDisplayAssociators ))

    ( nameSpace, className, entity_namespace_type ) = cgiEnv.GetNamespaceType()
    # If nameSpace is not provided, it is set to "root/CIMV2" by default.
    if not className:
        lib_common.ErrorMessageHtml("Class name should not be empty")

    wmiHost = cgiEnv.GetHost()

    # wmiHost=RCHATEAU-HP ns=root\cimv2 cls=Win32_ComputerSystem id=Name="RCHATEAU-HP"
    DEBUG("wmiHost=%s ns=%s cls=%s id=%s", wmiHost, nameSpace, className, cgiEnv.m_entity_id)

    grph = cgiEnv.GetGraph()

    try:
        connWmi = lib_wmi.WmiConnect(wmiHost,nameSpace)
    except:
        exc = sys.exc_info()[1]
        lib_common.ErrorMessageHtml("entity_wmi.py: Cannot connect to WMI server %s with namespace %s: %s" % ( wmiHost,nameSpace, str(exc) ) )

    # Try to read the moniker, which is much faster,
    # but it does not always work if we do not have all the properties.
    cgiMoniker = cgiEnv.GetParameters("xid")
    DEBUG("entity_wmi.py cgiMoniker=[%s]", cgiMoniker )

    objList = WmiReadWithMoniker( cgiEnv, cgiMoniker )
    if objList is None:
        # If no object associated with the moniker, then tries a WQL query which might return several objects.
        # BEWARE: This is slow and less efficient than using WMI filters.
        objList = WmiReadWithQuery( cgiEnv, connWmi, className )

    wmiInstanceUrl = lib_util.EntityUrlFromMoniker( cgiMoniker )

    # Possible problem because this associates a single URL with possibly several objects ??
    wmiInstanceNode = lib_common.NodeUrl(wmiInstanceUrl)

    # In principle, there should be only one object to display.
    # TODO: If several instances, the instance node must be recreated.
    for objWmi in objList:
        DEBUG("entity_wmi.py objWmi=[%s]", str(objWmi) )

        DispWmiProperties(grph, connWmi, wmiInstanceNode, objWmi, displayNoneValues, className )

        # Displaying these classes is very slow, several minutes for 100 elements.
        # It would be better to have another link.
        # rchref = wmi.WMI().query("select * from Win32_UserAccount where Name='rchateau'")[0].references()
        if not lib_wmi.WmiTooManyInstances( className ):
            try:
                DispWmiReferences(grph,wmiInstanceNode,objWmi,cgiMoniker)
            except:
                exc = sys.exc_info()[1]
                WARNING("entity_wmi.py Exception=%s", str(exc) )
        else:
            # Prefixc with a dot so it is displayed first.
            grph.add( ( wmiInstanceNode, lib_common.MakeProp(".REFERENCES"), lib_common.NodeLiteral( "DISABLED" ) ) )

        # Displaying the associators is conditional because it slows things.
        # TODO: How to select this option with D3 ?????
        if displayAssociators:
            # This class appears everywhere, so not not display its references, it would be too long.
            if className == "Win32_ComputerSystem":
                grph.add( ( wmiInstanceNode, lib_common.MakeProp(".ASSOCIATORS"), lib_common.NodeLiteral( "DISABLED" ) ) )
            else:
                DisplayObjectAssociators(grph,wmiInstanceNode,objWmi,cgiMoniker)

    # Adds the class node to the instance.
    wmiClassNode = lib_wmi.WmiAddClassNode(grph,connWmi,wmiInstanceNode, wmiHost, nameSpace, className, lib_common.MakeProp(className) )

    # Now displays the base class, up to the top.
    lib_wmi.WmiAddBaseClasses(grph,connWmi,wmiClassNode,wmiHost, nameSpace, className)

    # Now tries to find the equivalent object in the Survol terminology.
    AddSurvolObjectFromWmi(grph,wmiInstanceNode,connWmi,className,objList)

    # TODO: Embetant car il faut le faire pour toutes les classes.
    # Et en plus on perd le nom de la propriete.
    # cgiEnv.OutCgiRdf("LAYOUT_RECT",['root\\cimv2:CIM_Datafile'])
    # 'PartComponent' for 'root\\cimv2:CIM_Datafile'
    # 'Element' for 'root\\cimv2:Win32_DCOMApplication'
    # 'Antecedent' for 'CIM_DataFile'
    cgiEnv.OutCgiRdf("LAYOUT_TWOPI",[lib_common.MakeProp('PartComponent'),lib_common.MakeProp('Element'),lib_common.MakeProp('Antecedent')])
    # cgiEnv.OutCgiRdf("LAYOUT_SPLINE",[lib_common.MakeProp('PartComponent'),lib_common.MakeProp('Element'),lib_common.MakeProp('Antecedent')])

# TODO: Must add a link to our URL, entity.py etc...

if __name__ == '__main__':
    Main()
