#!/usr/bin/python

import sys
import cgi
import itertools
import pywbem # Might be pywbem or python3-pywbem.
import wbem_utils
import yawn_render

def _get_prop_type(prop):
    """
    @param prop is either pywbem.CIMParameter or pywbem.CIMProperty
    @return type of property, which can be:
           dictionary representing reference to object name
             containing ( 'className', 'ns' ) keys
           string representing any other type
    """
    value = prop.value
    res = '<UNKNOWN>'
    if ( prop.reference_class is None
       and ( prop.type != 'reference'
           or not isinstance(value, pywbem.CIMInstanceName))):
        res = prop.type
    else:
        res = {'className' : None }
        if prop.reference_class is not None:
            res['className'] = prop.reference_class
        else:
            if isinstance(value, list):
                value = value[0] if len(value) else None
            if isinstance(value, pywbem.CIMInstanceName):
                res['className'] = value.classname
                res['ns'] = value.namespace
    return res

def get_class_item_details(class_name, item):

    res = { 'name'         : item.name
          , 'is_deprecated': False
          # whether the item is declared be current class or
          # by some parent class
          , 'is_local'     : False
          # class, that defines this item (may be None)
          , 'class_origin' : None
          , 'is_key'       : False
          , 'is_array'     : False
          , 'is_method'    : False
          , 'is_required'  : False
          , 'is_valuemap'  : False
          , 'valuemap'     : []
          , 'values'       : {}
          , 'array_size'   : None
          , 'value'        : None
          , 'value_orig'   : None
          # only valid for method
          , 'args'         : []
          , 'type'         : _get_prop_type(item)
          # all less interesting qualifiers sorted by name
          , 'qualifiers'   : []
          }

    value = item.value

    if item.is_array:
        res['is_array'] = item.is_array
        res['array_size'] = item.array_size

    if value is not None:
        if (   item.qualifiers.has_key('values')
           and item.qualifiers.has_key('valuemap')):
            res['value'] = yawn_render.mapped_value2str(value, item.qualifiers)
        elif item.reference_class is not None:
            res['value'] = value
        else:
            res['value'] = yawn_render.val2str(value)

    if hasattr(item, 'class_origin'):
        res['is_local'] = item.class_origin == class_name
        res['class_origin'] = item.class_origin
    if item.qualifiers.has_key('description'):
        res['description'] = item.qualifiers['description'].value
    else:
        res['description'] = None
    for qualifier in item.qualifiers.values():
        if qualifier.name.lower() in (
                'description', 'key', 'required'):
            continue
        res['qualifiers'].append(
                (qualifier.name, yawn_render.val2str(qualifier.value)))

    return res




def DisplayClass(conn,className):
    try:
        klass = conn.GetClass(
                ClassName=className,
                LocalOnly=False,
                IncludeClassOrigin=True,
                IncludeQualifiers=True)

    except Exception:
        exc = sys.exc_info()[1]
        print("GetClass className="+className+". Caught:"+str(exc)+"<br>")

    print("<br><table border=1>")
    print("<tr>")
    print("<td>Superclass</td>")
    print("<td>"+str(klass.superclass)+"</td>")
    print("</tr>")

    print("<tr>")
    print("<td>association</td>")
    print("<td>"+str(klass.qualifiers.has_key('association'))+"</td>")
    print("</tr>")

    print("<tr>")
    print("<td>aggregation</td>")
    print("<td>"+str(klass.qualifiers.has_key('aggregation'))+"</td>")
    print("</tr>")

    print("<tr>")
    print("<td>description</td>")
    print("<td>"+str(klass.qualifiers.has_key('description'))+"</td>")
    print("</tr>")

    for q in klass.qualifiers.values():
        print("<tr>")
        print("<td>Qualifier:"+str(q.name)+"</td>")
        print("<td>"+str(q.value)+"</td>")
        print("</tr>")


    for item in klass.properties.values():
        print("<tr>")
        print("<td>Property:"+str(q.name)+"</td>")
        print("<td>"+str(q.value)+"</td>")
        print("<td><table border=1 bgcolor='pink'>")
        gcid = get_class_item_details( className, item)
        for kk in gcid:
            print("<tr>")
            print("<td>")
            print(str(kk))
            print("</td>")
            print("<td>")
            print(str(gcid[kk]))
            print("</td>")
            print("</tr>")
        print("</table></td>")

        print("</tr>")

    print("</table><br><br>")

# Notes: Pour les associations TUT_ProcessChildren, ne vaudrait-t-il pas mieux avoir un array de sous-processes ?
# Par ailleurs,WQL permet-il de rechercher sur des proprietes de type association ? A fortiori si ce sont des arrays ?
#
# Il faut une fonction qui renvoie une classe ou bien None si une propriete est une association.
# Ainsi on peut generer le lien.
# Quelle est la difference entre une association, et une classe normale contenant des refs ?
#
# J imagine que le type de la propriete est un InstanceName: Oui mais on la recoit par Cgi.
# Dommage de devoir deserialiser une InstanceName alors que justement on utilise Cgi
# pour ne pas packager la suite de clefs-valeurs.
# Par exemple au lieu d'ecrire:
#
#&Child=%22root/cimv2:TUT_UnixProcess.Handle=%228%22,OSCreationClassName=%22Linux_OperatingSystem%22,OSName=%22Unknown-30-b5-c2-02-0c-b5-2.home%22,CSCreationClassName=%22Linux_ComputerSystem%22,CSName=%22Unknown-30-b5-c2-02-0c-b5-2.home%22,CreationClassName=%22TUT_UnixProcess%22%22
#
#On aurait:
#
#&Child.ns=root/cimv2&Child.classname=TUT_UnixProcess&Child.Handle="8"&Child.OSCreationClassName="Linux_OperatingSystem"&Child.OSName="Unknown-30-b5-c2-02-0c-b5-2.home"&Child.CSCreationClassName="Linux_ComputerSystem"&Child.CSName="Unknown-30-b5-c2-02-0c-b5-2.home"&Child.CreationClassName="TUT_UnixProcess"
#
# Quid des arrays ?
# Certes on pourrait utiliser le compactage mais ca m'embete car conceptuellement on se lie a pywbem.
#
#
# Test WMI et WbemTest:
#
# https://msdn.microsoft.com/en-us/library/aa392902%28v=vs.85%29.aspx
# "SELECT * FROM __InstanceModificationEvent WITHIN 10 WHERE " & _
#    "TargetInstance ISA 'Win32_Service'" & _
#    " AND TargetInstance._Class = 'win32_TerminalService'"
#
# ("ASSOCIATORS OF {Win32_NetworkAdapterConfiguration.index=123456} WHERE ResultClass=Win32_NetworkAdapter"
#
# "ASSOCIATORS OF {Win32_Printer.DeviceID = "LaserJet 5"} WHERE AssocClass = Win32_PrinterShare""
#
# REFERENCES OF {Win32_Printer.DeviceID = 'printername'}
#
# SELECT all FROM __InstanceCreationEvent  WHERE TargetInstance ISA 'Win32_NTLogEvent'
#
# SELECT * FROM RegistryValueChangeEvent
#  WHERE Hive='HKEY_LOCAL_MACHINE' and
#        Keypath='SYSTEM\\ControlSet001\\Control' and
#        Valuename = 'CurrentUser'"
#
#
#
#
#
#
#
wbem_utils.Headers()

print("""<html>
<head></head>
<body>
""")

keyBindings = dict()

arguments = cgi.FieldStorage()
for cgiKey in arguments.keys():
    cgiVal = arguments.getfirst( cgiKey )
    if cgiKey == "classname":
        className = cgiVal
    elif cgiKey == "ns":
        nameSpace = cgiVal
    elif cgiKey == "url":
        cgiUrl = cgiVal
    else:
        keyBindings[cgiKey] = cgiVal

# http://127.0.0.1/Survol/wbem/EnumInstanceNames.py?classname=TUT_UnixProcess&ns=root/cimv2&url=http://192.168.1.88
print( "Objects of class "+wbem_utils.HrefClassName(className, nameSpace, cgiUrl) + "<br>" )

conn = wbem_utils.WbemConnection(cgiUrl)

DisplayClass(conn,className)

try:
    instanceNameObject = pywbem.CIMInstanceName(className,keyBindings,None,nameSpace)
except Exception:
    exc = sys.exc_info()[1]
    print("CIMInstanceName nameSpace="+nameSpace+ " className="+className+". Caught:"+str(exc)+"<br>")


try:
    instObj = conn.GetInstance( instanceNameObject )
    wbem_utils.PrintObjToHtml( [ list(instObj.items()) ] )
    print("<br>")
except Exception:
    exc = sys.exc_info()[1]
    print("nameSpace="+str(nameSpace)+ " className="+str(className)+" inst="+str(instanceNameObject)+". Caught:"+str(exc)+"<br>")

# Pas la peine d afficher les infos comme ca mais plutot
# se servir des infos sur la classe.
# http://127.0.0.1:1234/GetClass/TUT_UnixProcess?url=http%3A%2F%2F192.168.1.88&verify=0&ns=root%2Fcimv2
# Notamment il faut connaitre les classes de bases.
# Et surtout chercher les associations, les classes vers lesquelles on pointe.

# Faire un match incomplet.
# Peut etre que le tableau de description des classes pourrait mapper "Handle" vers "id" ?

# Dans notre cas, On n'a pas besoin de tous ces champs pour definir un process.
# http://127.0.0.1/Survol/wbem/GetInstance.py?classname=TUT_UnixProcess&ns=root/cimv2&url=http://192.168.1.88&Handle=1779&OSCreationClassName=Linux_OperatingSystem&OSName=Unknown-30-b5-c2-02-0c-b5-2.home&CSCreationClassName=Linux_ComputerSystem&CSName=Unknown-30-b5-c2-02-0c-b5-2.home&CreationClassName=TUT_UnixProcess
#http://127.0.0.1/Survol/wbem/GetInstance.py?classname=TUT_UnixProcess&ns=root/cimv2
# &url=http://192.168.1.88
# &Handle=1779
# &OSCreationClassName=Linux_OperatingSystem
# &OSName=Unknown-30-b5-c2-02-0c-b5-2.home
# &CSCreationClassName=Linux_ComputerSystem
# &CSName=Unknown-30-b5-c2-02-0c-b5-2.home
# &CreationClassName=TUT_UnixProcess
#
# Du cote de nos scripts on ne connaitra que CIM_UnixProcess ou meme encore CIM_Process.
# Donc nos scripts doivent extraire le pid de tous ces champs.
# Et inversement, uniquement avec le pid on doit aller chercher le bon objet WBEM.



##########################################


print("Query<br>")

print("<table border=1>")

print("<tr>")
print("<td>Classname</td>")
print("<td>"+className+"</td>")
print("</tr>")

print("<tr>")
print("<td>Namespace</td>")
print("<td>"+nameSpace+"</td>")
print("</tr>")

for key in keyBindings:
    val = keyBindings[key]
    print("<tr>")
    print("<td>"+str(key)+"</td>")
    print("<td>"+str(val)+"</td>")
    print("</tr>")

print("</table>")

# On peut fort bien fabriquer des liens vers une instance de Yawn.
# Par defaut cette instance a la meme root url que nous.
# L'installaton aux cotes de Yawn suppose seulement la copie des fichiers.
# Il faut pouvoir etre appele a partir de wsgi et de mod_python.
# S'arranger pour que Yawn n'aie pas forcement besoin de wsgi.
# Ou bien partir de celui de mod_python qui est moins chouette.

# Les proprietes viennent d'un CIM_InstanceName qui est passe clef par clef.
# L'avantage est qu'on tolere un parametre manquant.
wqlQuery = 'select * from ' + className
qryDelim = " where "
for key in keyBindings:
    val = keyBindings[key]
    wqlQuery += qryDelim + key + '="' + str(val) + '"'
    qryDelim = " and "



# This is for debugging.
# wqlQuery = 'select * from TUT_UnixProcess where Handle = "1848"'

print("WQL:'" + wqlQuery + "'<br>")
print("nameSpace=" + nameSpace + "<br>")

# qryResu = FromQuery( conn, theQry, nameSpace)
try:
    qryResu = conn.ExecQuery(QueryLanguage="WQL", Query=wqlQuery, namespace=nameSpace)
    print("Len qryResu="+str(len(qryResu)) + "<br>")
except Exception:
    exc = sys.exc_info()[1]
    wbem_utils.ThrowException(" Error executing query:" + wqlQuery + ". Caught:" +str(exc) )

# Ici, il faut savoir dans les proprietes, ce qui est un nom de classe,
# en fait ce qui est autre chose qu'une bete valeur.

print("<table border='1'>")
for instQry in qryResu:
    try:
        # Returned values are CMI_Instance, but are not addressable.
        # http://pywbem.sourceforge.net/docs/apiref/0.8.0-dev.r728/docs/index.html

        for it in instQry.iteritems():
            print("<tr>")
            print("<td>"+str(it[0])+"</td>")
            print("<td>"+str(it[1])+"</td>")
        print("</tr>")

        #Faire meme chose que   get_class_props dans yawn mais en plus rapide car par la suite
        #faudra faire du mapping avec le reste.
        #Ne pas se cantonner a mapper wbem avec noooootre code mais avec tous les utilitaires
        #qui ont besoin d un objet systeme. A la limite il faudrait un mapping par script:
        #Ou bien on decrete que chaque script prend en entree et en sortie que du wbem.
        #que chaque script se charqge de mapper vers les utilitaires system qu'il utilise.
        #En revanche le prog appelant se charge de leir ca avec le contenu du cimom.
        #Ainsi, la notion de provider est vachement enrichie.


    except Exception:
        exc = sys.exc_info()[1]
        print("nameSpace="+str(nameSpace)+ " className="+str(className)+" inst="+str(instanceNameObject)+". Caught:"+str(exc)+"<br>")

print("</table>")
print("<br>")


print("<br>")


print("<br>Finished")

# Dans WMI, Win32_Process derive de CIM_Process mais n;est defini que par Win32_Process.Handle="123"
# Pour nous, TUT_UnixProcess derive de CIM_UnixProcess qui derive de CIM_Process, et son CIM_InstanceName est:
# string 	CSCreationClassName 	Linux_ComputerSystem
# string 	CSName 	Unknown-30-b5-c2-02-0c-b5-2.home
# string 	CreationClassName 	TUT_UnixProcess
# string 	Handle 	1
# string 	OSCreationClassName 	Linux_OperatingSystem
# string 	OSName 	Unknown-30-b5-c2-02-0c-b5-2.home
#
#
# Toutefois, Win32_Process a aussi CSName et OSName
# CreationClassName = Win32_Process
# CSName = RCHATEAU-HP
# CSCreationClassName = Win32_ComputerSystem
# *Handle = 10364 : Avec une etoile car c'est la clef ???
# OSCreationClassName = Win32_OperatingSystem
# OSName = Microsoft Windows 7 Professional |C:\windows|\Device\Harddisk0\Partition2

# Apparemment, les deux definissent explicitement la machine mais pour Win32_Process ca ne fait
# pas partie de la clef, et de plus il faut peut-etre un appariement dependant de la classe.
# Alors qu'on aurait idealement voulu identifier le mneme objet dans deux repositories.
# Mais est-ce possible dans le cas general ? Il faudrait que ca fasse partie de la specification etc...
# De plus, il faudra faire un nslookup sur CSName: La aussi, on est dependant de la classe.
# Pour que l'appariement se fasse dans RDF, il faudra donc une transformation CIM => RDF qui soit "NON AMBIGUE",
# donc contienne la machine en adresse IP, ce qui ne peut se faire qu'en tenant compte de la classe.
# Nos URLs contiennent "url=xxx" et, meme s;ils premettent de faire des requetes dans CIM ou WMI,
# sont non ambigus et permettent l'appariement du meme objet dans plusieurs repositories.

# Afficher les machines trouvees avec SLP, en RDF.
# Idem le voisinage reseau qui accepte WMI (Si ca existe).
# C est ce qui fait l interet de RDF car on ne peut pas injecter du WBEM sans MOF.
# Comment en RDF apparier les objects si les classes ne sont pas exactement les memes ?
# Et pour les associations, qu'ont elles de plus qu'une arete ?
#
# Ultimement, nos URLS sont comme ca:
#
#def EncodeEntityId(entity_type,entity_id):
#	if isinstance( entity_id, RemoteEntityId ):
#		return "xid=%s@%s:%s" % ( EncodeUri(entity_id.m_host), entity_type , entity_id.m_entity_id )
#	else:
#		return "xid=%s:%s" % ( entity_type , entity_id )
#
# Mais les URLs WBEM sont bien plus riches. Et peuvent eventuellement renvoyer a plusieurs objects:
# On ne veut pas se cantonner a un id unique.
# Le plus immediat est peut-etre de laisser tomber nos urls et de generaliser:
# Ou alors, il faudrait que pour chaque classe, on sache convertir notre id "unique"
# en suite de clef-valeur.
# C est deja ce qu'on fait avec les fonctions SymbolUri() ou OracleTableUri().
# On va pour chacune de ces classes definir des fonctions de serialisations d'URL.
#
# Autre probleme pour OracleTableUri: La classe n'existe pas dans WBEM,
# on n'a pas le provider.
# Il est plus pythonique de definir "sources_types/process/__init__.py". En revanche si on importe
# le module "sources_types/hostname" ca va executer tous les xxx.py qui s'y trouvent ce qu'on ne veut pas faire DU TOUT.
# On peut peut-etre creer des directories "revlib/process/__init__.py" dans lesquels on mettra aussi la serialization
# des URLs.
#
# Aller chercher le parametre "id" a partir de l'URLs:
# hostname = cgiEnv.GetId("127.0.0.1")
# Comme nos URLs seront fabriques classe par classe, pas de probleme.
# Helas ca manque de generalite mais peut-on en avoir ?
# Pour le moment, GetId fera le meme decodage que maintenant.
#
# Pour acceder a la classe et ses fonctions de serializations, il faudrait eviter
# d'importer le module mais plutot avoir une map renvoyant une factory.