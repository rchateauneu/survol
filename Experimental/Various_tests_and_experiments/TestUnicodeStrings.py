# Affichage dans Firefox:
"Le Figaro - Arts Expositions : Néfertiti : l'homme derrière le chef-d'œuvre"
"Marqués récemment"

# Fichier recu du script cgi_dyn.py
# encode('latin-1')
"Marqu\u00e9s r\u00e9cemment"
"Le Figaro - Arts Expositions : N\u00e9fertiti : l'homme derri\u00e8re le chef-d'&#339;uvre"
"Union et Solidarit\u00e9 des Fran\u00e7ais de Grande-Bretagne"



# encode utf-8	
"Marqu\u00e9s r\u00e9cemment",
"Union et Solidarit\u00e9 des Fran\u00e7ais de Grande-Bretagne"
"Le Figaro - Arts Expositions : N\u00e9fertiti : l'homme derri\u00e8re le chef-d'&#339;uvre",
	
Dans le fichier, on lit pourtant "charset": "ISO-8859-1"

Contenu du fichier a l'origine:
"Marqu\u00e9s r\u00e9cemment",
"Le Figaro - Arts Expositions : N\u00e9fertiti : l'homme derri\u00e8re le chef-d'&#339;uvre"
"Union et Solidarit\u00e9 des Fran\u00e7ais de Grande-Bretagne"

Message d'erreur:
'ascii' codec can't encode character u'\xe9' in position 5: ordinal not in range(128)
args = ('ascii', u'Marqu\xe9s r\xe9cemment', 5, 6, 'ordinal not in range(128)')

Latin-1: e accent aigu = e9
Et donc la chaine a ete modifiee ???
e aigu= c3a9 en utf-8 ?
Cette commande printf '\xc3\xa9\n'
affiche bien e accent aigu.

Definition unicode=00E9: Ce seraient les encodages qui sont differents.

Notre locale:
	LANG=fr_FR.UTF-8



PROCHAINE ETAPE: Rajouter "u" devant les chaines foireuses, dans le json.
Et aussi piger pourquoi justement elles n'y sont pas mises
quand o sauve le fichier??????
final_data_to_write = json.dumps(myDict, encoding="XXX")
Mais il parait que par defaut c'est de l'utf-8 ? On va verifier.
