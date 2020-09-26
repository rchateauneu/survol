1>2# : ^
'''
@REM Create an installer in wxwidget for Apache, IIS etc.

py -3.6 -m venv %TMP%\survol-env
@REM py -2.7 -m virtualenv %TMP%\survol-env

%TMP%\survol-env\Scripts\python --version
%TMP%\survol-env\Scripts\pip --version
%TMP%\survol-env\Scripts\pip install survol
%TMP%\survol-env\Scripts\python -c "import survol;print('v=',survol.__version__);import survol.scripts.cgiserver;print('f=',survol.scripts.cgiserver.__file__)"

pushd %TMP%\survol-env\Lib\site-packages
%TMP%\survol-env\Scripts\python %TMP%\survol-env\Lib\site-packages\survol\scripts\cgiserver.py -b webbrowser
popd

exit /b
