$! BUILD_LIBXML.COM
$!
$! Build the LIBXML object library
$!
$! Ensure the logical name LIBXML is defined to point to the LIBXML source 
$! directory. This procedure creates an object library LIBXML.OLB in the LIBXML
$! directory. After the library is built, you can link LIBXML routines into
$! your code with the command  $ LINK your_modules,LIBXML:LIBXML.OLB/LIBRARY
$! 
$!- configuration -------------------------------------------------------------
$!
$!- compile command.  If p1="nowarn" suppress the expected warning types
$!
$   cc_command = "CC/DEBUG/NOOPT"
$   if p1.eqs."NOWARN" then 		-
      cc_command = cc_command + "/WARN=DISABLE=(FLOATOVERFL,NOMAINUFLO)"
$!
$!- list of sources to be built into the LIBXML library.  Compare this list
$!  to the definition of "libxml2_la_SOURCES" in the file MAKEFILE.
$!
$   sources = "SAX.c entities.c encoding.c error.c parserInternals.c parser.c"
$   sources = sources + " tree.c hash.c list.c xmlIO.c xmlmemory.c uri.c valid.c"
$   sources = sources + " xlink.c HTMLparser.c HTMLtree.c debugXML.c xpath.c "
$   sources = sources + " xpointer.c xinclude.c nanohttp.c nanoftp.c "
$   sources = sources + " DOCBparser.c catalog.c globals.c threads.c"
$!
$!- for VMS, we add in trio support
$!
$   sources = sources + " trio.c strio.c"
$!
$!- list of main modules to compile and link.  Compare this list to the
$!  definition of bin_PROGRAMS in MAKEFILE.
$!
$   bin_progs = "xmllint xmlcatalog"
$!
$!- list of test modules to compile and link.  Compare this list to the
$!  definition of noinst_PROGRAMS in MAKEFILE.
$!
$   test_progs = "testSAX testHTML testXPath testURI testDocbook"
$!
$!- set up build logicals -----------------------------------------------------\
$!
$   if f$trnlnm("xml_srcdir").eqs.""
$   then
$     globfile = f$search("[...]globals.c")
$     if globfile.eqs.""
$     then
$	write sys$output "Can't locate globals.c.  You need to define a XML_SRCDIR logical"
$     else
$	srcdir = f$element(0,"]",globfile)+ "]"
$	define/process xml_srcdir "''srcdir'"
$       write sys$output "Defining xml_srcdir as ""''srcdir'"""
$     endif
$   endif
$!
$   if f$trnlnm("libxml").eqs."" 
$   then 
$     globfile = f$search("[...]globals.h")
$     if globfile.nes.""
$     then
$	write sys$output "Can't locate globals.h.  You need to define a LIBXML logical"
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
$ if f$search("LIBXML.OLB").eqs."" then library/create LIBXML.OLB
$!
$ goto start_here
$ start_here:	  ! move this line to debug/rerun parts of this command file
$!
$!- compile modules into the library ------------------------------------------
$!
$ lib_command   = "LIBRARY/REPLACE LIBXML.OLB"
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
$     if next_source.eqs."xpath.c"
$     then
$	call build 'next_source' /IEEE_MODE=UNDERFLOW_TO_ZERO/FLOAT=IEEE
$     else
$       call build 'next_source'
$     endif
$     s_no = s_no + 1
$     goto source_loop
$!
$   endif
$!
$!- now build self-test programs ----------------------------------------------
$!
$! these pograms are built as ordinary modules into LIBXML.OLB.  Here they
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
$     call build 'next_prog'.c /IEEE_MODE=UNDERFLOW_TO_ZERO/FLOAT=IEEE
$     p_no = p_no + 1
$     goto prog_loop
$!
$   endif
$!
$!- Th-th-th-th-th-that's all folks! ------------------------------------------
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
$   write sys$output "Compiling ",p1,p2,"..."
$   cc_command /object='object_file 'source_file' 'p2'
$!
$!- insert into library if command defined
$   if lib_command.nes.""  then lib_command 'object_file'
$!
$!- link module if command defined
$   if link_command.nes."" 
$   then
$	text = f$element(0,".",p1)	! lose the ".c"
$	write sys$output "Linking ",text,"..."
$	link_command 'object_file',-
      		[]libxml.olb/library
$   endif
$!
$EXIT_BUILD:
$   exit $status
$!
$endsubroutine
