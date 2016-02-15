#!/usr/bin/python

import cgi
import cgitb; cgitb.enable() # Optional; for debugging only


# We receive one URL as a parameter, a meta-cgi producing a RDF document.
# We call this CGI several times, and merge all the triplets:
# We then eliminate duplicates, and maybe keep only the triplets 
# appearing more than X times.

# The CGI parameters are:
# The input CGI
# A tempo, a number of calls ?
# A lower limit.

# This could be combined with the merge of several CGIs 
# but we prefer to keep things simple for the moment.

# On utilise les memes classes que cgi_tcpdump:
# Creation automatique du serveur, serialisation du cache interne calcule en continu
# par le serveur.
# On peut dedier un serveur a l'URL parametre mais on peut aussi avoir un seul
# serveur et plusieurs caches. Ca va etre ce script qui va decider ou non de creer
# un process serveur par url a moyenner.

# On utilise le meme framework pour tous les traitements accumulatifs d'URL,
# et ca pourrait meme etre le meme script, qui recoit l'operation a appliquer.

Quelle est la tache de fond du serveur et meme y en a-t-il une ?
Faut il qu'il echantillone ou bien peut il etre confiant qiue les donneees
ne sont pas perdues? Mais si'l:l n'cah ntillonne pas, ikl ne paut pas 
calculer par rapport au temps.


# On scanne les arguments dans ce bloc, attention a la creation d'un sous-process.
if __name__ == '__main__':
	print("MAIN PROCESS")

	Lire les args

	Tester presence serveur pour cet URL.

