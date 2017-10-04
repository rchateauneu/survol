#!/usr/bin/python

"""
Generate HTML report
"""

# Afficher enm html la liste de tous les scripts et les appeler pour faire un rapport html + svg.
# On peut aussi faire la difference entre deux appels separes par un intervalle.
#Sauvegarde dans un directory tous les X intervalles.
# On clique dans les enumerate et on ajoute les noms des classes WMI et WBEM selon le cas: meme logique
#Drop down des noms des classes, pour chaque classe, les noms des scripts.
#Pour WMI./WBEM: On a que les associators et les attributs.

#On a un champ pour rentrer une regex : Pour nous, applicable que pour la caption et les attributs.
# On va utiliser une separateur special si on veut une comparaison.
# Et on ajoute un attribut special "caption~".

#Pour Wmi/wbem, appicable a tous champs grace a WQL.
#On peut rentrer des valeurs pour faire l equiva;ent dune requete SQL./
#Dans un second temps, requetes en cascades.
#Sauver formulaires en json.

# Il faut que ca puisse etre equivalent a la liste des urls d'un "merge".
# Il suffit qu on puisse recevoir en CGI un url.

# Ici, edition dynamique de la forme.
# On complete dynamique la page avec du javascript.
# On peuyt commencer en HTML pur.
# Meme logique si on complete la forme dynamiquement,

# Les scritps en general pourraient fournir la liste des classes qu ils renvoient.
# On pourrait le deduire en examinant les modules dont depend un script.
# Pour enumerate, c est un peu different car on veut en plus une enumeration.
#
# Le enumerate des host permet en plus d'ajouter des scripts d'autres hosts.
# Ce qu il faudrait faire des maintenant: Click-droit sur un host renvoie WBEM, WMI et eventuellement notre agent.

# format json:
# On peut specifier le host.
#
# "host"
# "plus","
#
#