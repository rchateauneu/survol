#!/usr/bin/env python

#  Installation.
# L avantage avec un setup est que ca devient accessible de Apache et IIS,
# sans devoir specifier le PATH !!!!
# En revanche faudra surement virer revlib ce qui va amener enormement de fichier dans le meme dir.
# Et meme supprimer peut-etre htlib ce qui est tres embetant.
#
# On veut remplacer:
# http://primhillcomputers.ddns.net/Survol/survol/entity.py
# http://127.0.0.1:8000/survol/entity.py
#
# par:
# http://primhillcomputers.ddns.net/survol/entity.py
# http://127.0.0.1:8000/survol/entity.py
#
# Un des problemes est que la presence des scripts dans le directory "htbin"
# est une contrainte (Style cgiscripts) mais on peut probablement la supprimer.
# Ce qui est plus embetant est qu'en supprimant htlib et revlib on se retrouve
# avec plein de fichiers dans le meme dossier ???
#
# Detecter la presence de "/survol/" n'est pas fiable.
#

import sys

# Consider setuptools.setup
from distutils.core import setup
from setuptools import find_packages

sys.stdout.write("Packages=%s\n"%find_packages())

#	  data_files=['*.htm','*.js','*.css','Docs/*.txt'],

# Must add htm and js files. Which directory ?
# Problem because the HTTP server, in the cgiserver.py configuration,
# is pointing directory to the Python packages.
# => Copy ui/Images into survol/Images and make a Python data directory.
# ui is also an independant static HTML/Javascript website.
#
# What is the traditional way to install html files ?
# And the easiest way to install them in Apache or any other HTTP server ?
#
# We should deliver two installers:
# * setup.py which installs the agent and also the UI while we are at it.
# * a simple static HTML website installer, using only "ui" directory.
#
# Docs is not copied anywhere.

setup(
    name='survol',
    version='1.0dev',
    description='Understanding legacy applications',
    author='Remi Chateauneu',
    author_email='remi.chateauneu@primhillcomputers.com',
    url='http://www.primhillcomputers.com/survol.htm',
    packages=find_packages(),
    package_dir = {"survol": "survol"},
    include_package_data=True,
    entry_points = { 'console_scripts': [
        'survol_cgiserver = survol.scripts.cgiserver:RunCgiServer',
        'survol_wsgiserver = survol.scripts.wsgiserver:RunWsgiServer',
    ]},
    requires=['rdflib','cgi','six'],
    # scripts=['cgiserver.py','wsgiserver.py','webserver.py'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Python Software Foundation License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: JavaScript',
        'Topic :: Software Development :: Bug Tracking',
        'Topic :: Education',
        'Topic :: Software Development :: Documentation',
        'Topic :: System :: Systems Administration',
        'Topic :: Documentation'
    ]
    )
