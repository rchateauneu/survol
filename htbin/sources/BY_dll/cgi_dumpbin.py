# Returns symbols associated to a DLL.

# Trouver un moyen de passer un parametre a un cgi :
# · Créer des URL qu’on injecte dans un fichier dot. Ca exige une passe speciale qui va reconnaitre la nature des nœuds.
# · Sur un SVG donne, il faut pouvoir developper plusieurs nœuds 
#   (c’est-à-dire merger avec des urls contenant ce nœud comme parametre).
# · Peut-etre style de merge ou, pour chaque nœud d’un type donne, 
#   on charge un pattern d’URL en ajoutant ce nœud comme parameter. 
#   Peut-etre pratique mais on risque d’avoir un graphe enorme. Pas incompatible avec le reste.
# · Quand on cliquerait un node, ca rappellerait le meme URL mais en ajoutant comme nouvel argument CGI, 
#   l’URL implicitement cree en cliquant ce nœud (Ou check-box auquel cas on retire le parametre 
#   (En fait un URL) de la liste d’url parametres CGI. 
#   On peut faire ca plus facilement si on affiche un url sous forme d’une liste de triplets, 
#   avec une check-box pour chaque triplet (Signifiant : « expansion pour un type d’URL 
#   admettant ce type de nœud comme paramètre)
# · Comment qualifier dynamiquement, qu’un URL doit prendre comme parametre un nœud d’un type donne ? 
#   Aussi, ca implique que le nom d’un nœud le qualifie entierement : On peut aller chercher un fichier, 
#   voir un process sur une machine donnee etc… 
#   Eventuellement, cet identifiant unique est affiche sous forme de raccourci.
# · Retour sur les points d’entrée dans les DLL/so : 
#   On parle bien d’un point d’entree dans une DLL donnée : 
#   Pas forcement, c’est une abstraction. 
#   En revanche, permettre d’instrumenter la combinaison : symbole+fichier.





import os
import re

dll_file = "d:/build/WEST/Bin/Debug/Westminster.dll"

dumpbin = "\"c:/Program Files (x86)/Microsoft Visual Studio 10.0/VC/bin/amd64/dumpbin.exe\""
command = dumpbin + " " + dll_file + " /exports"

#        362  168 0111B5D0 ?CompareNoCase@AString@ole@@QBEHPBD@Z = ?CompareNoCase@AString@ole@@QBEHPBD@Z (public: int __thiscall ole:
rgx = re.compile('^ *[0-9A-F]+ *[0-9A-F]+ *[0-9A-F]+ ([^ ]+) = ([^ ]+)')

for lin in os.popen( command ):
	matchObj = re.match( rgx, lin )
	if matchObj:
		print( "OK :" + matchObj.group(1) )

