# Microsoft Developer Studio Project File - Name="libxml2_a" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libxml2_a - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libxml2_a.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libxml2_a.mak" CFG="libxml2_a - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libxml2_a - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libxml2_a - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libxml2_a - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libxml2_a___Win32_Release"
# PROP BASE Intermediate_Dir "libxml2_a___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "libxml2_a"
# PROP Intermediate_Dir "libxml2_a"
# PROP Target_Dir ""
F90=df.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "IN_LIBXML" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"libxml2_a\libxml2.lib"

!ELSEIF  "$(CFG)" == "libxml2_a - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libxml2_a___Win32_Debug"
# PROP BASE Intermediate_Dir "libxml2_a___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "libxml2_a"
# PROP Intermediate_Dir "libxml2_a"
# PROP Target_Dir ""
F90=df.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MD /W3 /Gm /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "IN_LIBXML" /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"libxml2_a\libxml2.lib"

!ENDIF 

# Begin Target

# Name "libxml2_a - Win32 Release"
# Name "libxml2_a - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\catalog.c
# End Source File
# Begin Source File

SOURCE=..\..\debugXML.c
# End Source File
# Begin Source File

SOURCE=..\..\DOCBparser.c
# End Source File
# Begin Source File

SOURCE=..\..\encoding.c
# End Source File
# Begin Source File

SOURCE=..\..\entities.c
# End Source File
# Begin Source File

SOURCE=..\..\error.c
# End Source File
# Begin Source File

SOURCE=..\..\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\HTMLparser.c
# End Source File
# Begin Source File

SOURCE=..\..\HTMLtree.c
# End Source File
# Begin Source File

SOURCE=..\..\list.c
# End Source File
# Begin Source File

SOURCE=..\..\nanoftp.c
# End Source File
# Begin Source File

SOURCE=..\..\nanohttp.c
# End Source File
# Begin Source File

SOURCE=..\..\parser.c
# End Source File
# Begin Source File

SOURCE=..\..\parserInternals.c
# End Source File
# Begin Source File

SOURCE=..\..\SAX.c
# End Source File
# Begin Source File

SOURCE=..\..\tree.c
# End Source File
# Begin Source File

SOURCE=..\..\uri.c
# End Source File
# Begin Source File

SOURCE=..\..\valid.c
# End Source File
# Begin Source File

SOURCE=..\..\xinclude.c
# End Source File
# Begin Source File

SOURCE=..\..\xlink.c
# End Source File
# Begin Source File

SOURCE=..\..\xmlIO.c
# End Source File
# Begin Source File

SOURCE=..\..\xmlmemory.c
# End Source File
# Begin Source File

SOURCE=..\..\xpath.c
# End Source File
# Begin Source File

SOURCE=..\..\xpointer.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\libxml\catalog.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\debugXML.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\DOCBparser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\encoding.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\entities.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\hash.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\HTMLparser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\HTMLtree.h
# End Source File
# Begin Source File

SOURCE=..\..\libxml.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\list.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\nanoftp.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\nanohttp.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\parser.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\parserInternals.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\SAX.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\tree.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\uri.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\valid.h
# End Source File
# Begin Source File

SOURCE=..\..\include\win32config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xinclude.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xlink.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xmlerror.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xmlIO.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xmlmemory.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xmlversion.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xmlwin32version.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xpath.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xpathInternals.h
# End Source File
# Begin Source File

SOURCE=..\..\include\libxml\xpointer.h
# End Source File
# End Group
# End Target
# End Project
