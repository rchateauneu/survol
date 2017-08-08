# Installation.
# L avantage avec un setup est que ca devient accessible de Apache et IIS,
# sans devoir specifier le PATH !!!!
# En revanche faudra surement virer revlib et meme peut etre htlib ce qui est tres embetant

from distutils.core import setup
setup(name='foo',
      version='1.0',
      py_modules=['foo'],
      )