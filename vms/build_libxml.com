$! BUILD_LIBXML.COM
$!
$! Build the LIBXML object library
$!
$! Ensure the logical name LIBXML is defined to point to the LIBXML source 
$! directory. This procedure creates an object library LIBXML.OLB in the LIBXML
$! directory. After the library is built, you can link LIBXML routines into
$! your code with the command  $ LINK your_modules,LIBXML:LIBXML.OLB/LIBRARY
$! 
$!	
$!------------------------------------------------------------------------------
$ cc_command = "CC/DEBUG/NOOPT"
$ lib_command = "LIBRARY/REPLACE LIBXML.OLB"
$!
$ exit_status = 1
$ saved_default = f$environment("default")
$ on error then goto ERROR_OUT 
$ set def libxml
$ if f$search("DEBUG.DIR").eqs."" then create/dir [.DEBUG]
$ if f$search("LIBXML.OLB").eqs."" then library/create LIBXML.OLB
$!
$ call COMPILE DEBUGXML.C       
$ call COMPILE ENCODING.C       
$ call COMPILE ENTITIES.C       
$ call COMPILE ERROR.C          
$ call COMPILE HTMLPARSER.C     
$ call COMPILE HTMLTREE.C       
$ call COMPILE NANOFTP.C        
$ call COMPILE NANOHTTP.C       
$ call COMPILE PARSER.C         
$ call COMPILE SAX.C            
$ call COMPILE TREE.C           
$ call COMPILE URI.C            
$ call COMPILE VALID.C          
$ call COMPILE XLINK.C          
$ call COMPILE XMLIO.C          
$ call COMPILE XMLLINT.C        
$ call COMPILE XMLMEMORY.C      
$ call COMPILE XPATH.C          
$!
$EXIT_OUT:
$ set def 'saved_default
$ exit 'exit_status
$!
$
$ERROR_OUT:
$ exit_status = $status
$ write sys$output 'f$message(exit_status)'
$ goto EXIT_OUT
$!
$COMPILE: subroutine
$   on warning then goto EXIT_COMPILE
$   source_file = p1
$   name = f$element(0,".",source_file)
$   object_file = f$fao("[.debug]!AS.OBJ",name)
$   cc_command /object='object_file 'source_file'
$   lib_command 'object_file'
$EXIT_COMPILE:
$   exit $status
$endsubroutine
