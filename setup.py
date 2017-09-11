#!/usr/bin/env python

import os
import sys

# Creation of the package:
# python setup.py sdist
#
# Installation:
# scripts\activate
# pip install ..\dist\survol-1.0.dev0.zip --upgrade --install-option="--port 12345"
#
#

# Consider setuptools.setup
from distutils.core import setup
from setuptools import find_packages

from setuptools.command.install import install

# https://stackoverflow.com/questions/677577/distutils-how-to-pass-a-user-defined-parameter-to-setup-py
#
# pip install -v displays methods calls and their outputs.
#
# The following methods are called, see -v option:
#    running install
#    Running initialize_options
#    The port number for install is: 12345
#    Custom installation. Port: 12345
class InstallCommand(install):
    # The html files can be copied at any place.
    # For example at ~/public_html on Unix, i.e. "Users Dir feature of Apache".
    user_options = install.user_options + [
        ('port=', 'p', 'Port number'),
        ('www=', 'w', 'Destination directory of the Web UI'),
    ]

    def initialize_options(self):
        print("Running initialize_options")
        install.initialize_options(self)
        self.port = 24680

        # By dfefault, cgiserver will pick its files from the Python installation directory,
        # and this is acceptable because their are part of the same package.

        # http://setuptools.readthedocs.io/en/latest/setuptools.html#automatic-script-creation
        # For the default destination of HTML pages, see also "pkg_resources" and the likes:
        # "The distutils normally install general "data files" to a platform-specific location (e.g. /usr/share)"
        # So it is possible to install the HTML pages in a normal directory, and also in a location,
        # standard for Python, where Python modules can retrieve them. and also the Python server.
        self.www = None

    def finalize_options(self):
        print('The port number for install is:%s' % self.port)
        install.finalize_options(self)

    def run(self):
        # This must be given to a parameter file for cgiserver.
        my_port = self.port

        # The HTML, css and js files must be copied at this place.
        # This avoids to have a HTTP server such as Apache or IIS,
        # pick its files from the Python installation dir.
        my_www = self.www

        # Also, the css and js files must be copied into the Python directory.

        print("Custom installation. Port:%s Dest dir=%s" % (my_port,my_www))
        if my_www:
            print("About to copy %s"%my_www)
        install.run(self)  # OR: install.do_egg_install(self)

# TODO: Explain installation in Apache:
# - When pointing to Python scripts.
# - or when using the CGI script survolcgi.


# http://peak.telecommunity.com/DevCenter/PythonEggs#accessing-package-resources
# from pkg_resources import resource_string
# foo_config = resource_string(__name__, 'foo.conf')

sys.stdout.write("Packages=%s\n"%find_packages())

#	  data_files=['*.htm','*.js','*.css','Docs/*.txt'],

# Problem because the HTTP server, in the cgiserver.py configuration,
# is pointing to directories in the Python packages.
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

# Quand on lance le script, on doit etre capable de le trouver www pour le copier.
# Et les positions respectives de "/survol" et "/www" ne sont plus les memes car:
# - On ne veut pas d'un module qui s'appelle www.
# - La partie SVG peut vouloir acceder a "www/images"
# On doit se proposer un numero de port pour les agents. Exploration en javascript,
# mais quid du cross-scripting.
#
# Il y a plusieurs taches:
# l'installation du module Python.
# => Eventuellement on y copie /images et /css.
# L'installation du serveur de cgi Python.
# => Eventuellement plusieurs installations: Apache, IIS etc...
#    Comment configurer la ou les installations (Numero de port ?)
# L'installation (et la copie des fichiers) du serveur de l'interface.
# => Eventuellement plusieurs installations: Apache, Tomcat etc...
# => Eventuellement meme installation que le CGI.
# => L'UI est informee de l'emplacement du CGI.
# => Pouvoir lancer la page HTML en local pur, et utiliser ActiveX.
#
# Quoiqu'il arrive, survol_cgiserver ouvrira toujours une fenetre.
#
# Apparemment, c'est pas de la tarte d'installer des donnees avec setup.py.
# Alors on pourrait tout changer:
# On a un seul module et des sous-modules:
# survol/agent : L'agent. Mais on va tout mettre dans survol pour ne pas devoir tout casser.
# survol/scripts
# survol/www avec les datas : Mais a condition qu;on puisse avoir des donnees.
#
# Comme ca, ca fournit a cgiserver.py d acceder "legalement" aux fichiers HTML au lieu
# de fourrager dans PYTHON PATH.
#
#
# data_files
# package_data={'templates':['*'],'static':['*'],'docs':['*'],},
#

# The current directory is where setup.py is.
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

extra_files = package_files('survol/www')

setup(
    name='survol',
    version='1.0dev',
    description='Understanding legacy applications',
    author='Remi Chateauneu',
    author_email='remi.chateauneu@primhillcomputers.com',
    url='http://www.primhillcomputers.com/survol.htm',
    packages=find_packages(),
    package_dir = {"survol": "survol"},
    # Ca n est pas recursif.
    # package_data={'survol':['www_test/*'],},
    package_data={'survol':extra_files,},
    # include_package_data=True,

    entry_points = { 'console_scripts': [
        'survol_cgiserver = survol.scripts.cgiserver:RunCgiServer',
        'survol_wsgiserver = survol.scripts.wsgiserver:RunWsgiServer',
        'survol_cgiscript = survol.scripts.survolcgi:SurvolCgi',
    ]},
    requires=['rdflib','cgi','six'],
    cmdclass={
        'install': InstallCommand,
    },
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

################################################################################

# APPENDIX: Some tips about the installation of Survol under Apache.
#
# Two installations types are possible:
# (1) With the CGI scripts survolcgi.exe, which just need to be accessible,
# and imports survol Python modules, installed by sdist.
# (2) Or if Apache runs sources files from the development directory or from the installed packages.
# This is what is demonstrated here.

#Alias /Survol "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle"
#<Directory "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle" >
#    Options Indexes FollowSymLinks Includes ExecCGI
#    Allow from all
#    AddHandler cgi-script .py
#	# http://stackoverflow.com/questions/2036577/how-do-i-ignore-the-perl-shebang-on-windows-with-apache-2
#	ScriptInterpreterSource Registry-Strict
#	# SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\revlib
#</Directory>

################################################################################

## Appendix'appendix: How to install Yawn, which is an HTML navigator into OpenLmi (Pegasus) objects and classes.
## apache's configuration file for yawn using wsgi
## We could add this content in yawn.conf and incldue the content.
#WSGIScriptAlias /yawn "C:/Users/rchateau/Developpement/ReverseEngineeringApps/pywbem_all/pywbem_sourceforge/yawn2/trunk/mod_wsgi/yawn_wsgi.py"

## For development convenience, no need to install anything because we point to the development files.
#<Directory "C:/Users/rchateau/Developpement/ReverseEngineeringApps/pywbem_all/pywbem_sourceforge/yawn2/trunk/mod_wsgi>
#    # Options Indexes FollowSymLinks Includes ExecCGI
#    Options ExecCGI
#    # Allow from all
#    WSGIPassAuthorization On
#    # AddHandler cgi-script .py
#	# http://stackoverflow.com/questions/2036577/how-do-i-ignore-the-perl-shebang-on-windows-with-apache-2
#	# ScriptInterpreterSource Registry-Strict
#	SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\pywbem_all\pywbem_sourceforge\yawn2\trunk\mod_wsgi\pywbem_yawn
#</Directory>

################################################################################

