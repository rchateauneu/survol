#!/usr/bin/python

import sys
import cgi
import pywbem # Might be pywbem or python3-pywbem.
import wbem_utils





###################################################

def EnumerateInstrumentedClasses(conn,namSpac):
    """
    Enumerates only those class names, that are instrumented (there
    is a provider under broker implementing its interface.
    """
    fetched_classes = []
    def get_class(conn,cname):
        """Obtain class from broker and store it in cache."""
        fetched_classes.append(cname)
        return conn.GetClass(ClassName=cname,
                   LocalOnly=True, PropertyList=[],
                   IncludeQualifiers=False, IncludeClassOrigin=False)

    start_class = '.'

    caps = wbem_utils.GetCapabilitiesForInstrumentation(conn,namSpac)


    print("caps<br>")
    for cap in caps:
        print("cap="+str(cap['ClassName'])+"<br>")
    print("<br>")

    deep_dict = {start_class:[]}

    for cap in caps:
        if namSpac not in cap['Namespaces']:
            continue
        if cap['ClassName'] in fetched_classes:
            continue
        klass = get_class(conn,cap['ClassName'])
        if klass.superclass is None:
            deep_dict[start_class].append(klass.classname)
        else:
            try:
                deep_dict[klass.superclass].append(klass.classname)
            except KeyError:
                deep_dict[klass.superclass] = [klass.classname]
            while klass.superclass is not None:
                if klass.superclass in fetched_classes:
                    break
                klass = get_class(conn,klass.superclass)
                if klass.superclass is None and klass.superclass not in deep_dict[start_class]:
                    deep_dict[start_class].append(klass.classname)
                elif klass.superclass in deep_dict:
                    if (  klass.classname
                       not in deep_dict[klass.superclass]):
                        deep_dict[klass.superclass].append( klass.classname)
                    break
                else:
                    deep_dict[klass.superclass] = [klass.classname]
    return deep_dict

###################################################

def GetClassesTree(conn,theNamSpace):
    kwargs = {'DeepInheritance': True}
    # kwargs['ClassName'] = None
    kwargs['LocalOnly'] = True
    kwargs['IncludeQualifiers'] = False
    kwargs['IncludeClassOrigin'] = False

    klasses = conn.EnumerateClasses(namespace=theNamSpace,**kwargs)

    # print("Got the list:" + str(len(klasses))+"<br>")

    tree_classes = dict()
    for klass in klasses:
        # This does not work. WHY ?
        # tree_classes.get( klass.superclass, [] ).append( klass )
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

    return tree_classes

###################################################


def MakeInstrumentedRecu(inTreeClass, outTreeClass, topclassNam, theNamSpac, instrCla):
    try:
        if topclassNam in instrCla:
            # print("top "+topclassNam+" instrumented<br>")
            outTreeClass[topclassNam] = []
        for cl in inTreeClass[topclassNam]:
            clnam = cl.classname
            MakeInstrumentedRecu(inTreeClass, outTreeClass, clnam, theNamSpac, instrCla)

            if clnam in instrCla or clnam in outTreeClass:
                # This does not work. WHY ?
                # outTreeClass.get( klass.superclass, [] ).append( clnam )
                try:
                    outTreeClass[topclassNam].append(cl)
                except KeyError:
                    outTreeClass[topclassNam] = [cl]


    except KeyError:
        # No subclass.
        pass


def GetClassesTreeInstrumented(conn,theNamSpace):
    inTreeClass = GetClassesTree(conn,theNamSpace)
    outTreeClass = dict()
    instrCla = wbem_utils.GetCapabilitiesForInstrumentation(conn,theNamSpace)
    MakeInstrumentedRecu(inTreeClass, outTreeClass, None, theNamSpace, instrCla)

    # print("outTreeClass="+str(outTreeClass)+"<br>")
    return outTreeClass


###################################################

# Same as in EnumClassNames.py
def PrintClassRecu(tree_classes, theNamSpac, cgiUrl, topclassNam, margin):
    sys.stdout.write(margin + " " + wbem_utils.HrefClassName(topclassNam, theNamSpac, cgiUrl) + "<br>")
    margin += "----"
    try:
        for cl in tree_classes[topclassNam]:
            clnam = cl.classname
            PrintClassRecu(tree_classes, theNamSpac, cgiUrl, clnam, margin)
    except KeyError:
        # No subclass.
        pass

# For debugging purpose only.
def PrintClassRecuFilter(tree_classes, theNamSpac, cgiUrl, topclass, margin,filter):

    if not topclass is None:
        if topclass in filter:
            sys.stdout.write(margin + " " + wbem_utils.HrefClassName(topclass, theNamSpac, cgiUrl) + " IN<br>")
        else:
            sys.stdout.write(margin + " " + wbem_utils.HrefClassName(topclass, theNamSpac, cgiUrl) + " OUT<br>")

    margin += "----"
    try:
        for cl in tree_classes[topclass]:
            clnam = cl.classname
            PrintClassRecuFilter(tree_classes, theNamSpac, cgiUrl, clnam, margin,filter)
    except KeyError:
        # No subclass.
        pass


arguments = cgi.FieldStorage()
nameSpace = arguments["ns"].value
cgiUrl = arguments["url"].value

conn = wbem_utils.WbemConnection(cgiUrl)

wbem_utils.Headers()

print("""<html>
<head></head>
<body>
""")

print("Classes in namespace:"+nameSpace+"<br>")

print("Classes:")

treeClassesAll = GetClassesTree(conn,nameSpace)

print("Len tree_classes=" + str(len(treeClassesAll))+"<br>")

# Debugging purpose only.
#instrCla = wbem_utils.GetCapabilitiesForInstrumentation(conn,nameSpace)
#PrintClassRecuFilter(treeClassesAll, nameSpace, cgiUrl, None, "xx", instrCla)

print("<br><br>")

treeClassesFiltered = GetClassesTreeInstrumented(conn,nameSpace)
PrintClassRecu(treeClassesFiltered, nameSpace, cgiUrl, None, "yy")

print("<br><br>")

#PrintClassRecuFilter(treeClassesFiltered, nameSpace, cgiUrl, None, "zz", instrCla)

print("<br><br>")

print('<br><a href="EnumNamespaces.py?url=' + cgiUrl + '">Namespaces in ' + cgiUrl + '</a><br>')

print("""<br>Finished
</body>
</html>
""")
