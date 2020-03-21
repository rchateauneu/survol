#!/usr/bin/env python

import os
import sys
try:
    # Python 2
    from future_builtins import filter
except ImportError:
    # Python 3
    pass

import ast

# pip install ..\dist\survol-1.0.dev0.zip --upgrade --install-option="--port 12345"

# TODO: Have a look to setuptools.setup
from distutils import log
from distutils.core import setup
from setuptools import find_packages

from setuptools.command.install import install
from setuptools.command.install_lib import install_lib

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
    # TODO: This is not used yet.
    user_options = install.user_options + [
        ('port=', 'p', 'CGI server port number'),
        ('www=', 'w', 'Web UI destination directory'),
    ]

    def initialize_options(self):
        print("Running initialize_options")
        install.initialize_options(self)
        self.port = 24680 # TODO: This is not used yet.

        # By default, cgiserver will pick its files from the Python installation directory,
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
            print("About to copy %s" % my_www)
        install.run(self)  # OR: install.do_egg_install(self)

class InstallLibCommand(install_lib):
    # On Linux, this converts Python files to proper Unix format,
    # and sets the executable flag.
    def _transform_linux_script(self, one_path):
        with open(one_path, 'rb') as input_stream:
            file_content = input_stream.readlines()

        # There must not be any CR character after this shebang line.
        if file_content[0].startswith(b"#!/usr/bin/env python"):
            log.info("Script file=%s l=%d end=%s"
                     % (one_path, len(file_content), str([ord(x) for x in file_content[0]])))
            try:
                # Maybe this file is a script. If so, remove "CRLF" at the end.
                lines_number = 0
                with open(one_path, 'wb') as output_stream:
                    for one_line in file_content:
                        if one_line.endswith(b'\r\n') or one_line.endswith(b'\n\r') :
                            output_stream.write(b"%s\n" % one_line[:-2])
                        else:
                            output_stream.write(one_line)
                        lines_number += 1

                log.info("Script written=%d" % lines_number)
                # Set executable flag for Linux CGI scripts.
                os.chmod(one_path, 0o744)
            except Exception as exc:
                log.error("Script err=%s" % exc)

    def copy_tree(
            self, infile, outfile,
            preserve_mode=1, preserve_times=1, preserve_symlinks=0, level=1
    ):
        # This is called on, for the top-level infile='build\\lib'
        if sys.platform.startswith("lin"):
            library_top = os.path.join(infile, "survol")
            for library_root, library_dirs, library_files in os.walk(library_top):
                for one_file in library_files:
                    if one_file.endswith(".py"):
                        one_path = os.path.join(library_root, one_file)
                        self._transform_linux_script(one_path)

        return install_lib.copy_tree(self, infile, outfile,
            preserve_mode, preserve_times, preserve_symlinks, level)


# TODO: Explain installation in Apache when pointing to Python scripts.

# The current directory is where setup.py is.
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

extra_files = package_files('survol/www')

# The zip archive contains directories: docs, survol and tests.

with open(os.path.join('survol', '__init__.py')) as f:
    __version__ = ast.parse(next(filter(lambda line: line.startswith('__version__'), f))).body[0].value.s

with open('README.txt') as readme_file:
    README = readme_file.read()

# FIXME: survol.__doc__ = '\nSurvol library\n' ...

setup(
    name='survol',
    version=__version__,
    description='Understanding legacy applications',
    long_description=README,
    author='Primhill Computers',
    author_email='contact@primhillcomputers.com',
    url='http://www.primhillcomputers.com/survol.html',
    packages=find_packages(),
    package_dir = {"survol": "survol"},
    # This is apparently not recursive.
    package_data={'survol': extra_files},
    entry_points = { 'console_scripts': [
        'survol_cgiserver = survol.scripts.cgiserver:start_server_forever',
        'survol_wsgiserver = survol.scripts.wsgiserver:run_wsgi_server',
    ]},
    # These packages are not needed to run dockit.py which is strictly standalone.
    install_requires=['psutil', 'rdflib'],
    cmdclass={
        'install': InstallCommand,
        'install_lib': InstallLibCommand,
    },

    # scripts=['cgiserver.py','wsgiserver.py'],
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
# (1) With the CGI scripts cgiserver, which just need to be accessible,
# and imports survol Python modules, installed by sdist.
# (2) Or if Apache runs the sources files from the development directory or from the installed packages.
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

