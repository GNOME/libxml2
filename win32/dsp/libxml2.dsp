# Microsoft Developer Studio Project File - Name="libxml2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libxml2 - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libxml2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libxml2.mak" CFG="libxml2 - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libxml2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libxml2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libxml2 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libxml2___Win32_Release"
# PROP BASE Intermediate_Dir "libxml2___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "libxml2"
# PROP Intermediate_Dir "libxml2"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "libxml2_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# Begin Custom Build - Creating static library libxml2_a.lib...
InputPath=.\libxml2\libxml2.dll
SOURCE="$(InputPath)"

"libxml2\libxml2_a.lib" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	lib /nologo /out:libxml2\libxml2_a.lib libxml2\*.obj

# End Custom Build

!ELSEIF  "$(CFG)" == "libxml2 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libxml2___Win32_Debug"
# PROP BASE Intermediate_Dir "libxml2___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "libxml2"
# PROP Intermediate_Dir "libxml2"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "libxml2_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MD /W3 /Gm /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /FR /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# Begin Custom Build - Creating static library libxml2_a.lib...
InputPath=.\libxml2\libxml2.dll
SOURCE="$(InputPath)"

"libxml2\libxml2_a.lib" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	lib /nologo /out:libxml2\libxml2_a.lib libxml2\*.obj

# End Custom Build

!ENDIF 

# Begin Target

# Name "libxml2 - Win32 Release"
# Name "libxml2 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\c14n.c
# End Source File
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

SOURCE=..\..\globals.c
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

SOURCE=.\libxml2.def
# End Source File
# Begin Source File

SOURCE=.\libxml2.def.src

!IF  "$(CFG)" == "libxml2 - Win32 Release"

USERDEP__LIBXM="../../include/libxml/xmlversion.h"	
# Begin Custom Build
InputPath=.\libxml2.def.src

"libxml2.def" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	cl /I"..\.." /I"..\..\include" /nologo /EP $(InputPath) > libxml2.def

# End Custom Build

!ELSEIF  "$(CFG)" == "libxml2 - Win32 Debug"

# PROP Ignore_Default_Tool 1
USERDEP__LIBXM="../../include/libxml/xmlversion.h"	
# Begin Custom Build
InputPath=.\libxml2.def.src

"libxml2.def" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	cl /I"..\.." /I"..\..\include" /nologo /EP $(InputPath) > libxml2.def

# End Custom Build

!ENDIF 

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

SOURCE=..\..\threads.c
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

SOURCE=..\..\include\libxml\c14n.h
# End Source File
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

SOURCE=..\..\include\libxml\globals.h
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
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
