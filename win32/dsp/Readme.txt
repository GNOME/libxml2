Hi there.

You can find the project files for MSVC 6.0 and higher in win32/dsp/
subdirectory of the source tree. You should load the file libxml2.dsw
into the IDE. This is the workspace file which contains all projects
and their interdependencies.

Check the file xmlwin32version.h for optional features and enable or
disable them, as it suits you. The defaults are apropriate for most 
people, so there is usually no need to mess with this.

For libxml2, there is a single project file which builds both static 
and shared library in a single run. When you build the project libxml2, 
you will find the following files in your win32/dsp/libxml2 
subdirectory:

  libxml2.dll     shared library
  libxml2.lib     import library for dynamic link
  libxml2_a.lib   static library

Other project files produce a single executable in a subdirectory which
shares the name with the project.

All object files produced by the compiler end up in the same
directory for each project, no matter if you compile with debugging
turned on or not. This means that a release build shall overwite the 
debug build and vice versa. This makes the dependency tracking easier,
but there are people who don't like this for some reason.

If you receive few compiler warnings, ignore them. These are harmless
and shall dissapear in the future.

5. January 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>