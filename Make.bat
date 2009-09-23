@call Clean.bat
@Set /P FPC=
@Call ..\..\Builder\build.bat Makefile.dlp
@Set FPC=