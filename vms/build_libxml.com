$! BUILD_LIBXML.COM
$!
$! Build the LIBXML library
$!
$! Arguments:
$!
$!	"NOWARN" - suppress known/expected warnings
$!   	"DEBUG"  - build everythign in debug
$!
$! This procedure creates an object library XMLOLB:LIBXML.OLB directory.  
$! After the library is built, you can link LIBXML routines into
$! your code with the command  
$!
$!	$ LINK your_modules,XMLOLB:LIBXML.OLB/LIBRARY
$! 
$! Change History
$! --------------
$! Command file author : John A Fotheringham (jaf@jafsoft.com)
$! Last update         : 2 Nov 2001
$!
$!- configuration -------------------------------------------------------------
$!
$!- compile command.  If p1="nowarn" suppress the expected warning types
$!
$   if p1.eqs."DEBUG" .or. p2.eqs."DEBUG"
$   then
$     debug = "Y"
$     cc_command = "CC/DEBUG/NOOPT"
$   else
$     debug = "N"
$     cc_command = "CC"
$   endif
$   if p1.eqs."NOWARN" then 		-
      cc_command = cc_command + "/WARN=DISABLE=(FLOATOVERFL,NOMAINUFLO)"
$!
$!- list of sources to be built into the LIBXML library.  Compare this list
$!  to the definition of "libxml2_la_SOURCES" in the file MAKEFILE.IN.
$!  Currently this definition includes the list WITH_TRIO_SOURCES_TRUE
$!
$   sources = "SAX.c entities.c encoding.c error.c parserInternals.c parser.c"
$   sources = sources + " tree.c hash.c list.c xmlIO.c xmlmemory.c uri.c valid.c"
$   sources = sources + " xlink.c HTMLparser.c HTMLtree.c debugXML.c xpath.c "
$   sources = sources + " xpointer.c xinclude.c nanohttp.c nanoftp.c "
$   sources = sources + " DOCBparser.c catalog.c globals.c threads.c"
$   sources = sources + " trio.c strio.c"
$!
$!- list of main modules to compile and link.  Compare this list to the
$!  definition of bin_PROGRAMS in MAKEFILE.IN
$!
$   bin_progs = "xmllint xmlcatalog"
$!
$!- list of test modules to compile and link.  Compare this list to the
$!  definition of noinst_PROGRAMS in MAKEFILE.
$!
$   test_progs = "testSAX testHTML testXPath testURI testDocbook testThreads"
$!
$!- set up build logicals -----------------------------------------------------\
$!
$   if f$trnlnm("XMLOLB").eqs.""
$   then
$     write sys$output ""
$     write sys$output "	You need to define a XMLOLB logical directory to"
$     write sys$output "	point to the directory containing your CMS object"
$     write sys$output "	libraries.  This should already contain LIBXML.OLB"
$     write sys$output "	from the libxml package, and will be the directory"
$     write sys$output "	the new LIBXSLT.OLB library will be placed in"
$     write sys$output ""
$     exit
$   endif
$!
$   if f$trnlnm("xml_srcdir").eqs.""
$   then
$     globfile = f$search("[-...]globals.c")
$     if globfile.eqs.""
$     then
$	write sys$output "Can't locate globals.c.  You need to manually define a XML_SRCDIR logical"
$	exit
$     else
$	srcdir = f$element(0,"]",globfile)+ "]"
$	define/process xml_srcdir "''srcdir'"
$       write sys$output "Defining xml_srcdir as ""''srcdir'"""
$     endif
$   endif
$!
$   if f$trnlnm("libxml").eqs."" 
$   then 
$     globfile = f$search("[-...]globals.h")
$     if globfile.eqs.""
$     then
$	write sys$output "Can't locate globals.h.  You need to manually define a LIBXML logical"
$	exit
$     else
$	includedir = f$element(0,"]",globfile)+ "]"
$	define/process libxml "''includedir'"
$       write sys$output "Defining libxml as ""''includedir'"""
$     endif
$   endif
$!
$!- set up error handling (such as it is) -------------------------------------
$!
$ exit_status = 1
$ saved_default = f$environment("default")
$ on error then goto ERROR_OUT 
$ on control_y then goto ERROR_OUT 
$!
$!- move to the source directory and create any necessary subdirs and the 
$!  object library
$!
$ set def xml_srcdir
$ if f$search("DEBUG.DIR").eqs."" then create/dir [.DEBUG]
$ if f$search("XMLOLB:LIBXML.OLB").eqs."" 
$ then 
$   write sys$output "Creating new object library XMLOLB:LIBXML.OLB"
$   library/create XMLOLB:LIBXML.OLB
$ endif
$!
$ goto start_here
$ start_here:	  ! move this line to debug/rerun parts of this command file
$!
$!- compile modules into the library ------------------------------------------
$!
$ lib_command   = "LIBRARY/REPLACE XMLOLB:LIBXML.OLB"
$ link_command	= ""
$!
$ write sys$output ""
$ write sys$output "Building modules into the LIBXML object library"
$ write sys$output ""
$!
$ s_no = 0
$ sources = f$edit(sources,"COMPRESS")
$!
$ source_loop:
$!
$   next_source = f$element (S_no," ",sources)
$   if next_source.nes."" .and. next_source.nes." "
$   then
$!
$     on error then goto ERROR_OUT 
$     on control_y then goto ERROR_OUT 
$     if next_source.eqs."xpath.c"
$     then
$	call build 'next_source' /IEEE_MODE=UNDERFLOW_TO_ZERO/FLOAT=IEEE
$     else
$       if next_source.eqs."trio.c"
$       then
$	  call build 'next_source' /WARN=DISABLE=UNINIT1 
$	else
$         call build 'next_source'
$	endif
$     endif
$     s_no = s_no + 1
$     goto source_loop
$!
$   endif
$!
$!- now build self-test programs ----------------------------------------------
$!
$! these pograms are built as ordinary modules into XMLOLB:LIBXML.OLB.  Here they
$! are built a second time with /DEFINE=(STANDALONE) in which case a main()
$! is also compiled into the module
$ 
$ lib_command	= ""
$ link_command	= "LINK"
$!
$ write sys$output ""
$ write sys$output "Building STANDALONE self-test programs"
$ write sys$output ""
$!
$ call build NANOFTP.C	/DEFINE=(STANDALONE)
$ call build NANOHTTP.C	/DEFINE=(STANDALONE)
$ call build TRIONAN.C	/DEFINE=(STANDALONE)/IEEE_MODE=UNDERFLOW_TO_ZERO/FLOAT=IEEE
$!
$!- now build main and test programs ------------------------------------------
$!
$!
$ lib_command	= ""
$ link_command	= "LINK"
$!
$ write sys$output ""
$ write sys$output "Building main programs and test programs"
$ write sys$output ""
$!
$ p_no = 0
$ all_progs = bin_progs + " " + test_progs
$ all_progs = f$edit(all_progs,"COMPRESS")
$!
$ prog_loop:
$!
$   next_prog = f$element (p_no," ",all_progs)
$   if next_prog.nes."" .and. next_prog.nes." "
$   then
$!
$     on error then goto ERROR_OUT 
$     on control_y then goto ERROR_OUT 
$     call build 'next_prog'.c /IEEE_MODE=UNDERFLOW_TO_ZERO/FLOAT=IEEE
$     p_no = p_no + 1
$     goto prog_loop
$!
$   endif
$!
$!- Th-th-th-th-th-that's all folks! ------------------------------------------
$!
$ goto exit_here ! move this line to avoid parts of this command file
$ exit_here:	  
$!
$ exit       
$ goto exit_out
$!
$!
$EXIT_OUT:
$!
$ purge/nolog [.debug]
$ set def 'saved_default
$ exit 'exit_status
$!
$
$ERROR_OUT:
$ exit_status = $status
$ write sys$output "''f$message(exit_status)'"
$ goto EXIT_OUT
$!
$!- the BUILD subroutine.  Compile then insert into library or link as required
$!
$BUILD: subroutine
$   on warning then goto EXIT_BUILD
$   source_file = p1
$   name = f$element(0,".",source_file)
$   object_file = f$fao("[.debug]!AS.OBJ",name)
$!
$!- compile
$!
$   write sys$output "Compiling ",p1," ",p2,"..."
$   cc_command'p2' /object='object_file 'source_file'
$!
$!- insert into library if command defined
$!
$   if lib_command.nes.""  then lib_command 'object_file'
$!
$!- link module if command defined
$   if link_command.nes."" 
$   then
$	text = f$element(0,".",p1)	! lose the ".c"
$	write sys$output "Linking ",text,"..."
$	opts = ""
$	if debug then opts = "/DEBUG"
$	link_command'opts' 'object_file',-
      		XMLOLB:libxml.olb/library
$   endif
$!
$EXIT_BUILD:
$   exit $status
$!
$endsubroutine
