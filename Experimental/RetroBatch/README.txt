dockit is a command-line tool which allows to capture system calls made by a process or a process tree.

It is a Python script which runs the target process under control of the famous strace or ltrace Linux commands. It creates, for each run:
* A txt file where the system calls are aggregated into bigger logical blocks.
* A summary XML file containing all process, files and sockets created
* A Dockerfile and the associated directory, to create a Docker image,
* Also, a raw log file containing the system calls, which allows to rerun the test.

It is a standalone script, compatible with Python 2 and Python 3. For the moment,
it works on Linux only. Porting to Microsoft Windows is planned.
It is also possible to port it to other Linux flavours.

How does it work:
=================

The script runs a command, or attaches to a process id, and reads the input produced by strace/ltrace, which produces a lot of information, which cannot be directly used. This log of system calls is then processed to produce a synthetic information.

Command line options:
=====================
dockit.py -h

Loaded packages cache file:FileToPackageCache.vps516494.localdomain.txt
Retrobatch: ./dockit.py <executable>
Monitors and factorizes systems calls.
  -h,--help                     This message.
  -v,--verbose                  Verbose mode (Cumulative).
  -w,--warning                  Display warnings (Cumulative).
  -s,--summary <CIM class>      Prints a summary at the end: Start end end time stamps, executable name,
                                loaded libraries, read/written/created files and timestamps, subprocesses tree.
                                Examples: -s 'Win32_LogicalDisk.DeviceID="C:",Prop1="Value1",Prop2="Value2"'
                                          -s 'CIM_DataFile:Category=["Others","Shared libraries"]'
  -D,--dockerfile               Generates a dockerfile.
  -p,--pid <pid>                Monitors a running process instead of starting an executable.
  -f,--format TXT|CSV|JSON      Output format. Default is TXT.
  -F,--summary-format TXT|XML   Summary output format. Default is XML.
  -i,--input <file name>        trace command input file.
  -l,--log <filename prefix>    trace command log output file.

  -t,--tracer strace|ltrace|cdb command for generating trace log

Examples:
=========

Typical strace or ltrace commands are:

Command ls with strace:
-----------------------
The default trace program is strace.

dockit.py ls
strace -q -qq -f -tt -T -s 200 -y -yy -e trace=desc,ipc,process,network,memory ls

Attaching to process 4233:
--------------------------
dockit.py -p 4233
strace -q -qq -f -tt -T -s 200 -y -yy -e trace=desc,ipc,process,network,memory -p 4233

Command ps, traced with ltrace:
-------------------------------
The command-line option -t allows to choose a tracer command.
dockit.py -t ltrace ps -ef
ltrace -tt -T -f -S -s 200 -e -*+getenv+*@SYS ps -ef

Command netstat. Stores the result:
-----------------------------------

dockit.py -l XYZ -t ltrace netstat
ltrace -tt -T -f -S -s 200 -e -*+getenv+*@SYS netstat

This generates several files:
XYZ.ltrace.29765.ini Contains the parameters to rerun this session.
XYZ.ltrace.29765.log All the logged system calls.
XYZ.ltrace.29765.txt Aggregated system calls.

Replay a session, and generates a Dockerfile:
---------------------------------------------
dockit.py -i XYZ.ltrace.29765.log -D

find docker.docker/ -ls
drwxrwxr-x  4096 May  8 22:53 docker.docker/
-rw-rw-r--   764 May  8 22:53 docker.docker/Dockerfile

This Dockerfile can be used to create a Docker image.

Run a session, create a summary file and a Dockerfile:
------------------------------------------------------

./dockit.py -l ABC -F XML -D grep xyz '*.py'
strace -q -qq -f -tt -T -s 200 -y -yy -e trace=desc,ipc,process,network,memory grep xyz *.py

This generates the files:
ABC.strace.29887.ini Session parameters.
ABC.strace.29887.log All system calls.
ABC.strace.29887.txt Aggregated system calls.
ABC.strace.29887.xml Summary of all resources.
ABC.strace.29887.docker:
    Dockerfile



Future directions:
==================

More aggregation of data 


(2) Reduction, aggregation et filtrage
On elimine ce qui est inutile, on aggrege des operations repetitives.
=> On discerne les blocs fonctionnels: Processes, fichiers, requetes SQL,
on separe les traitements differents: pics de traitement, pids, threads.
On connait le role de telle ou telle librairie.

(3) Matching avec les objects metiers.
On apparie les "traces" avec des objets metiers en fonctions
des time-stamps, pid, sockets, fichiers etc...

Qu'est ce qui est fait ?
========================
(1) sous Linux
(2) en partie seulement.

Par rapport a "Survol":
=======================
Survol est un outil interactif d'analyse et d'exploration d'un systeme existant.
Il fait des snapshots de ressources en cours d'execution ou d'exploitation,
et les presente dans plusieurs interface: WEB, texte, SVG etc...

Mine-IT apporte la dimension temporelle aux objets presente par Survol:
Ils sont orthogonaux en ceci que survol explore les relations
entre les objects a un instant T, tandis que Mine-IT suit leur evolution.
COMMANDES:

EXEMPLEQ:

Extension to process mining:
============================
L idee est d appliquer les concepts du "Process Mining" au deroulement technique d'un
systeme d informations, d un ensemble de taches, dont a priori on ne sait rien.

Qu'est ce que le process mining ? https://en.wikipedia.org/wiki/Process_mining#Overview
=================================
D'apres wikipedia, c'est un ensemble de techniques
issue du Business Process Management ( https://fr.wikipedia.org/wiki/Business_Process_Management ),
et qui permet l'analyse de processus metiers en partant de fichiers de logs,
c est a dire de l historique technique d une suite d'operations metiers.
Ces fichiers de logs peuvent etre crees par tout outil utilise par l entreprise,
et peuvent concerner toute ressource de celle-ci: Suite d operations client,
d'intervention du personnel, de transformations sur des produits etc...

Pendant le process mining, des algorithmes specifiques sont utilises sur les fichiers de logs
pour identifier des patters des tendances, extraire des details, aggreger des operations
de base.

Il suffit qu on puisse ramener chaque operation de base d'un log,
a un triplet: CaseId, Activite, timeStamp, pour que les algorithmes du Process Mining puisse s'appliquer.

Ici, on considere les ressoucres techniques comme faisant partie des ressources de l entreprise,
et composents au plus bas niveau des processus metiers.

C'est par exemple le meilleur modele des batches quotidiens.
Et meme sans documentation, cette informnation est toujours disponible.,
bien que tres technique et difficile a relier
aux objects metier; Mais cette relation existe.

L'objectif de MineIT est de relier les fichiers de logs des batchs,
que objets metiers du client, en s'appuyant sur les concepts du Process Mining.

D'emblee, quelques remarques:

* Generer des logs fiables, est une fonctionnalite en elle-meme,
que MineIT realise: Il n'y a donc pas besoin d'autres outils.
* Remonter des objets techniques aux ressources metiers: C'est un process iteratif,
par nature imprecis en l'absence de documentation, et toujours ameliorable.

