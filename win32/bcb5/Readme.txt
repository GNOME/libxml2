
Build for Borland C++ Builder 5 (libxml2 2.4.19)
===============================

This procedure will build the following file:

libxml2_a.lib	- static libxml library

libxml2_a.bpr	- for the static version

And build it. The resulting files should be in this directory afterwards.
There will be a lot of warnings which are supposed to be ignored.
If you want to reconfigure the package, you must edit the file
..\..\include\libxml\xmlversion.h

You must define the symbol WIN32 in all your projects to use the header
files.

April 2002, Moritz Both <moritz@daneben.de>
