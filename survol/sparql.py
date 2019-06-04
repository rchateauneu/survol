#!/usr/bin/python

"""
Mandatory SPARQL end-point

It extracts data from Survol, WMI or WBEM, then runs a Sparql query on the current RDF triplestore.
This triplestore can also be updated by events.
"""

# Ca n est pas la meme chose que les trois scripts specifiques qui prechargent le triplestore
# et renvoient sont contenu.
# Ici, on precharge le triplestore, mais on renvoie le  result de la requete Sparql.

# Ca doit remplacer aussi la recherche: Strings etc..., recherche sur des paths
# Il faudrait renvoyer des resultats au fur et a mesure,
# ou passer des parametres de recherche dans la query sparql.
