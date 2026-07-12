@REM TODO: These two lines do not work and should be fixed.
on break gosub gotabreak
on error gosub gotabreak

pushd D:\Developpement\Survol\survol\survol\
python scripts\cgiserver.py %*
:gotabreak
popd

@REM python %~dp0\survol\scripts\cgiserver.py %*