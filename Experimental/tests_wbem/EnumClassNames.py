#!/usr/bin/env python

import sys
import cgi
import pywbem # Might be pywbem or python3-pywbem.
import wbem_utils

def GetClassesTree(conn,theNamSpace):
    kwargs = {'DeepInheritance': True}
    # kwargs['ClassName'] = None
    kwargs['LocalOnly'] = True
    kwargs['IncludeQualifiers'] = False
    kwargs['IncludeClassOrigin'] = False

    # klasses = conn.EnumerateClasses(**kwargs)
    klasses = conn.EnumerateClasses(namespace=theNamSpace,**kwargs)

    print("Got the list:" + str(len(klasses)))

    tree_classes = dict()
    for klass in klasses:
        # print("Super="+str(klass.superclass))
        # tree_classes.get( klass.superclass, [] ).append( klass )
        try:
            tree_classes[klass.superclass].append(klass)
        except KeyError:
            tree_classes[klass.superclass] = [klass]

    return tree_classes


def PrintClassRecu(tree_classes, theNamSpac, cgiUrl, topclass, margin):
    sys.stdout.write(margin + " " + wbem_utils.HrefClassName(topclass, theNamSpac, cgiUrl) + "<br>")
    margin += "----"
    try:
        for cl in tree_classes[topclass]:
            clnam = cl.classname
            PrintClassRecu(tree_classes, theNamSpac, cgiUrl, clnam, margin)
    except KeyError:
        # No subclass.
        pass


# A la maison seulement
# conn2 = pywbem.WBEMConnection('http://192.168.1.88',  ('pegasus', 'toto'))
# DoAlltests(conn2)

arguments = cgi.FieldStorage()
nameSpace = arguments["ns"].value
cgiUrl = arguments["url"].value

conn = wbem_utils.WbemConnection(cgiUrl)

wbem_utils.Headers()

print("""<html>
<head></head>
<body>
""")

print('<br><a href="EnumNamespaces.py?url=' + cgiUrl + '">Namespaces in ' + cgiUrl + '</a><br>')

print("Classes in namespace:"+nameSpace+"<br>")

print("Classes:")
tree_classes = GetClassesTree(conn,nameSpace)

print("Len classes=" + str(len(tree_classes)))

# print("x="+str(tree_classes))
PrintClassRecu(tree_classes, nameSpace, cgiUrl, None, "")


print("""
</body>
</html>
""")


# Il faudrait que tous nos scripts puissent etre appeles comme des fonctions de facon
# a pouvoir utiliser wsgi ou mod_python.
#    * Charger dynamiquement un script / ou bien ajouter "if main" ...
#    * Remplir les arguments CGI avec les arguments de la fonction (Et donc wrapper "cgi")
#    * Nos Urls doivent etre differents (Correspondondre a WSGI ?)
#    * Pour en tirer parti, creer un objet "cache" qui soit un fichier ou bien de la memoire,
#      ou bien un objet d'environnement.