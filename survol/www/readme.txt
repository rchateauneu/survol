ui/images and CSS are correctly moved to a Python script because they need to be accessed both by the agent and the UI.
In fact we should have a separate module independantly installed on both environments.

Avec ca, en effet, c'est pas normal que lUI aille chercher ses images sur un autre site alors qu'il peut etrs bien en avoir une copie locale.
Le directory "ui" ne doit contenir que des data,
et doit pouvoir etre installe avec ou sans Python
Mais si Python l'installe, ca doit faire partie d'un module.
En fait, survol/ui devrait etre un zip que setup.py decompresserait.

Quand on lance cgiserver.py, il active en meme temps l'UI qui pointe donc sur les memes css et images que l agent.
Et l UI peut presupposer sans danger, l'emplacement de l'agent, il lui suffit de lire son propre URL.

Mais on peut lancer cgiserver.py sur l#UI seulement qui aura donc ses fichiers a disposition.
Mais ne saura pas a priori ou se trouve l'agent de la meme machine.

Quelle est la facon standard d'installer un petit site web fait d'HTML et de CSS ?
Est-ce que setup.py sait installer un site comme ca dans Apache ou autre ?
