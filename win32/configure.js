/* Configure script for libxml, specific for Windows with Scripting Host.
 * 
 * This script will configure the libxml build process and create necessary files.
 * Run it with an 'help', or an invalid option and it will tell you what options
 * it accepts.
 *
 * March 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>
 */

/* The source directory, relative to the one where this file resides. */
var srcDirXml = "..";
var srcDirUtils = "..";
/* The directory where we put the binaries after compilation. */
var binDir = "binaries";
/* Base name of what we are building. */
var baseName = "libxml2";
/* Configure file which contains the version and the output file where
   we can store our build configuration. */
var configFile = srcDirXml + "\\configure.in";
var versionFile = ".\\configure.txt";
/* Input and output files regarding the libxml features. The second
   output file is there for the compatibility reasons, otherwise it
   is identical to the first. */
var optsFileIn = srcDirXml + "\\include\\libxml\\xmlversion.h.in";
var optsFile = srcDirXml + "\\include\\libxml\\xmlversion.h";
var optsFile2 = srcDirXml + "\\include\\libxml\\xmlwin32version.h";
/* Version strings for the binary distribution. Will be filled later 
   in the code. */
var verMajor;
var verMinor;
var verMicro;
/* Libxml features. */
var withTrio = false;
var withThreads = false;
var withFtp = true;
var withHttp = true;
var withHtml = true;
var withC14n = true;
var withCatalog = true;
var withDocb = true;
var withXpath = true;
var withXptr = true;
var withXinclude = true;
var withIconv = true;
var withZlib = false;
var withDebug = true;
var withMemDebug = false;
var withSchemas = true;
var withRegExps = true;
/* Win32 build options. */
var buildDebug = 0;
var buildStatic = 0;
var buildPrefix = ".";
var buildBinPrefix = "$(PREFIX)\\bin";
var buildIncPrefix = "$(PREFIX)\\include";
var buildLibPrefix = "$(PREFIX)\\lib";
var buildSoPrefix = "$(PREFIX)\\lib";
var buildInclude = ".";
var buildLib = ".";
/* Local stuff */
var error = 0;

/* Helper function, transforms the option variable into the 'Enabled'
   or 'Disabled' string. */
function boolToStr(opt)
{
	if (opt == false)
		return "Disabled";
	else if (opt == true)
		return "Enabled";
	error = 1;
	return "Undefined";
}

/* Helper function, transforms the argument string into a boolean
   value. */
function strToBool(opt)
{
	if (opt == 0 || opt == "no")
		return false;
	else if (opt == 1 || opt == "yes")
		return true;
	error = 1;
	return false;
}

/* Displays the details about how to use this script. */
function usage()
{
	var txt;
	txt = "Usage:\n";
	txt += "  cscript " + WScript.ScriptName + " <options>\n";
	txt += "  cscript " + WScript.ScriptName + " help\n\n";
	txt += "Options can be specified in the form <option>=<value>, where the value is\n";
	txt += "either 'yes' or 'no'.\n\n";
	txt += "XML processor options, default value given in parentheses:\n\n";
	txt += "  trio:       Enable TRIO string manipulator (" + (withTrio? "yes" : "no")  + ")\n";
	txt += "  threads:    Enable thread safety (" + (withThreads? "yes" : "no")  + ") \n";
	txt += "  ftp:        Enable FTP client (" + (withFtp? "yes" : "no")  + ")\n";
	txt += "  http:       Enable HTTP client (" + (withHttp? "yes" : "no")  + ")\n";
	txt += "  html:       Enable HTML processor (" + (withHtml? "yes" : "no")  + ")\n";
	txt += "  c14n:       Enable C14N support (" + (withC14n? "yes" : "no")  + ")\n";
	txt += "  catalog:    Enable catalog support (" + (withCatalog? "yes" : "no")  + ")\n";
	txt += "  docb:       Enable DocBook support (" + (withDocb? "yes" : "no")  + ")\n";
	txt += "  xpath:      Enable XPath support (" + (withXpath? "yes" : "no")  + ")\n";
	txt += "  xptr:       Enable XPointer support (" + (withXptr? "yes" : "no")  + ")\n";
	txt += "  xinclude:   Enable XInclude support (" + (withXinclude? "yes" : "no")  + ")\n";
	txt += "  iconv:      Enable iconv support (" + (withIconv? "yes" : "no")  + ")\n";
	txt += "  zlib:       Enable zlib support (" + (withZlib? "yes" : "no")  + ")\n";
	txt += "  xml_debug:  Enable XML debbugging module (" + (withDebug? "yes" : "no")  + ")\n";
	txt += "  mem_debug:  Enable memory debugger (" + (withMemDebug? "yes" : "no")  + ")\n";
	txt += "  regexps:    Enable regular expressions (" + (withRegExps? "yes" : "no") + ")\n";
	txt += "  schemas:    Enable XML Schema support (" + (withSchemas? "yes" : "no")  + ")\n";
	txt += "\nWin32 build options, default value given in parentheses:\n\n";
	txt += "  debug:      Build unoptimised debug executables (" + (buildDebug? "yes" : "no")  + ")\n";
	txt += "  static:     Link xmllint statically to libxml2 (" + (buildStatic? "yes" : "no")  + ")\n";
	txt += "  prefix:     Base directory for the installation (" + buildPrefix + ")\n";
	txt += "  bindir:     Directory where xmllint and friends should be installed\n";
	txt += "              (" + buildBinPrefix + ")\n";
	txt += "  incdir:     Directory where headers should be installed\n";
	txt += "              (" + buildIncPrefix + ")\n";
	txt += "  libdir:     Directory where static and import libraries should be\n";
	txt += "              installed (" + buildLibPrefix + ")\n";
	txt += "  sodir:      Directory where shared libraries should be installed\n"; 
	txt += "              (" + buildSoPrefix + ")\n";
	txt += "  include:    Additional search path for the compiler, particularily\n";
	txt += "              where iconv headers can be found (" + buildInclude + ")\n";
	txt += "  lib:        Additional search path for the linker, particularily\n";
	txt += "              where iconv library can be found (" + buildLib + ")\n";
	WScript.Echo(txt);
}

/* Discovers the version we are working with by reading the apropriate
   configuration file. Despite its name, this also writes the configuration
   file included by our makefile. */
function discoverVersion()
{
	var fso, cf, vf, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	cf = fso.OpenTextFile(configFile, 1);
	vf = fso.CreateTextFile(versionFile, true);
	vf.WriteLine("# " + versionFile);
	vf.WriteLine("# This file is generated automatically by " + WScript.ScriptName + ".");
	vf.WriteBlankLines(1);
	while (cf.AtEndOfStream != true) {
		ln = cf.ReadLine();
		s = new String(ln);
		if (s.search(/^LIBXML_MAJOR_VERSION/) != -1) {
			vf.WriteLine(s);
			verMajor = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^LIBXML_MINOR_VERSION/) != -1) {
			vf.WriteLine(s);
			verMinor = s.substring(s.indexOf("=") + 1, s.length)
		} else if(s.search(/^LIBXML_MICRO_VERSION/) != -1) {
			vf.WriteLine(s);
			verMicro = s.substring(s.indexOf("=") + 1, s.length)
		}
	}
	cf.Close();
	vf.WriteLine("XML_SRCDIR=" + srcDirXml);
	vf.WriteLine("UTILS_SRCDIR=" + srcDirUtils);
	vf.WriteLine("BINDIR=" + binDir);
	vf.WriteLine("WITH_TRIO=" + (withTrio? "1" : "0"));
	vf.WriteLine("WITH_THREADS=" + (withThreads? "1" : "0"));
	vf.WriteLine("WITH_FTP=" + (withFtp? "1" : "0"));
	vf.WriteLine("WITH_HTTP=" + (withHttp? "1" : "0"));
	vf.WriteLine("WITH_HTML=" + (withHtml? "1" : "0"));
	vf.WriteLine("WITH_C14N=" + (withC14n? "1" : "0"));
	vf.WriteLine("WITH_CATALOG=" + (withCatalog? "1" : "0"));
	vf.WriteLine("WITH_DOCB=" + (withDocb? "1" : "0"));
	vf.WriteLine("WITH_XPATH=" + (withXpath? "1" : "0"));
	vf.WriteLine("WITH_XPTR=" + (withXptr? "1" : "0"));
	vf.WriteLine("WITH_XINCLUDE=" + (withXinclude? "1" : "0"));
	vf.WriteLine("WITH_ICONV=" + (withIconv? "1" : "0"));
	vf.WriteLine("WITH_ZLIB=" + (withZlib? "1" : "0"));
	vf.WriteLine("WITH_DEBUG=" + (withDebug? "1" : "0"));
	vf.WriteLine("WITH_MEM_DEBUG=" + (withMemDebug? "1" : "0"));
	vf.WriteLine("WITH_SCHEMAS=" + (withSchemas? "1" : "0"));
	vf.WriteLine("WITH_REGEXPS=" + (withRegExps? "1" : "0"));
	vf.WriteLine("DEBUG=" + (buildDebug? "1" : "0"));
	vf.WriteLine("STATIC=" + (buildStatic? "1" : "0"));
	vf.WriteLine("PREFIX=" + buildPrefix);
	vf.WriteLine("BINPREFIX=" + buildBinPrefix);
	vf.WriteLine("INCPREFIX=" + buildIncPrefix);
	vf.WriteLine("LIBPREFIX=" + buildLibPrefix);
	vf.WriteLine("SOPREFIX=" + buildSoPrefix);
	vf.WriteLine("INCLUDE=$(INCLUDE);" + buildInclude);
	vf.WriteLine("LIB=$(LIB);" + buildLib);
	vf.Close();
}

/* Configures libxml. This one will generate xmlversion.h from xmlversion.h.in
   taking what the user passed on the command line into account. */
function configureLibxml()
{
	var fso, ofi, of, ln, s;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	ofi = fso.OpenTextFile(optsFileIn, 1);
	of = fso.CreateTextFile(optsFile, true);
	while (ofi.AtEndOfStream != true) {
		ln = ofi.ReadLine();
		s = new String(ln);
		if (s.search(/\@VERSION\@/) != -1) {
			of.WriteLine(s.replace(/\@VERSION\@/, 
				verMajor + "." + verMinor + "." + verMicro));
		} else if (s.search(/\@LIBXML_VERSION_NUMBER\@/) != -1) {
			of.WriteLine(s.replace(/\@LIBXML_VERSION_NUMBER\@/, 
				verMajor*10000 + verMinor*100 + verMicro*1));
		} else if (s.search(/\@WITH_TRIO\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_TRIO\@/, withTrio? "1" : "0"));
		} else if (s.search(/\@WITH_THREADS\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_THREADS\@/, withThreads? "1" : "0"));
		} else if (s.search(/\@WITH_FTP\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_FTP\@/, withFtp? "1" : "0"));
		} else if (s.search(/\@WITH_HTTP\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_HTTP\@/, withHttp? "1" : "0"));
		} else if (s.search(/\@WITH_HTML\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_HTML\@/, withHtml? "1" : "0"));
		} else if (s.search(/\@WITH_C14N\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_C14N\@/, withC14n? "1" : "0"));
		} else if (s.search(/\@WITH_CATALOG\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_CATALOG\@/, withCatalog? "1" : "0"));
		} else if (s.search(/\@WITH_DOCB\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_DOCB\@/, withDocb? "1" : "0"));
		} else if (s.search(/\@WITH_XPATH\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_XPATH\@/, withXpath? "1" : "0"));
		} else if (s.search(/\@WITH_XPTR\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_XPTR\@/, withXptr? "1" : "0"));
		} else if (s.search(/\@WITH_XINCLUDE\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_XINCLUDE\@/, withXinclude? "1" : "0"));
		} else if (s.search(/\@WITH_ICONV\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_ICONV\@/, withIconv? "1" : "0"));
		} else if (s.search(/\@WITH_ZLIB\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_ZLIB\@/, withZlib? "1" : "0"));
		} else if (s.search(/\@WITH_DEBUG\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_DEBUG\@/, withDebug? "1" : "0"));
		} else if (s.search(/\@WITH_MEM_DEBUG\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_MEM_DEBUG\@/, withMemDebug? "1" : "0"));
		} else if (s.search(/\@WITH_SCHEMAS\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_SCHEMAS\@/, withSchemas? "1" : "0"));
		} else if (s.search(/\@WITH_REGEXPS\@/) != -1) {
			of.WriteLine(s.replace(/\@WITH_REGEXPS\@/, withRegExps? "1" : "0"));
		} else
			of.WriteLine(ln);
	}
	ofi.Close();
	of.Close();
	fso.CopyFile(optsFile, optsFile2, true);
}

/* Creates the readme file for the binary distribution of 'bname', for the
   version 'ver' in the file 'file'. This one is called from the Makefile when
   generating a binary distribution. The parameters are passed by make. */
function genReadme(bname, ver, file)
{
	var fso, f;
	fso = new ActiveXObject("Scripting.FileSystemObject");
	f = fso.CreateTextFile(file, true);
	f.WriteLine("  " + bname + " " + ver);
	f.WriteLine("  --------------");
	f.WriteBlankLines(1);
	f.WriteLine("  This is " + bname + ", version " + ver + ", binary package for the native Win32/IA32");
	f.WriteLine("platform.");
	f.WriteBlankLines(1);
	f.WriteLine("  The directory named 'include' contains the header files. Place its");
	f.WriteLine("contents somewhere where it can be found by the compiler.");
	f.WriteLine("  The directory which answers to the name 'lib' contains the static and");
	f.WriteLine("dynamic libraries. Place them somewhere where they can be found by the");
	f.WriteLine("linker. The files whose names end with '_a.lib' are aimed for static");
	f.WriteLine("linking, the other files are lib/dll pairs.");
	f.WriteLine("  The directory called 'util' contains various programs which count as a");
	f.WriteLine("part of " + bname + ".");
	f.WriteBlankLines(1);
	f.WriteLine("  If you plan to develop your own programme, in C, which uses " + bname + ", then");
	f.WriteLine("you should know what to do with the files in the binary package. If you don't,");
	f.WriteLine("know this, then please, please do some research on how to use a");
	f.WriteLine("third-party library in a C programme. The topic belongs to the very basics"); 
	f.WriteLine("and you will not be able to do much without that knowledge.");
	f.WriteBlankLines(1);
	f.WriteLine("  If you wish to use " + bname + " solely through the supplied utilities, such as");
	f.WriteLine("xmllint or xsltproc, then all you need to do is place the");
	f.WriteLine("contents of the 'lib' and 'util' directories from the binary package in a"); 
	f.WriteLine("directory on your disc which is mentioned in your PATH environment"); 
	f.WriteLine("variable. You can use an existing directory which is allready in the"); 
	f.WriteLine("path, such as 'C:\WINDOWS', or 'C:\WINNT'. You can also create a new"); 
	f.WriteLine("directory for " + bname + " and place the files there, but be sure to modify"); 
	f.WriteLine("the PATH environment variable and add that new directory to its list.");
	f.WriteBlankLines(1);
	f.WriteLine("  If you use other software which needs " + bname + ", such as Apache");
	f.WriteLine("Web Server in certain configurations, then please consult the"); 
	f.WriteLine("documentation of that software and see if it mentions something about");
	f.WriteLine("how it uses " + bname + " and how it expects it to be installed. If you find");
	f.WriteLine("nothing, then the default installation, as described in the previous"); 
	f.WriteLine("paragraph, should be suficient.");
	f.WriteBlankLines(1);
	f.WriteLine("  If there is something you cannot keep for yourself, such as a problem,");
	f.WriteLine("a cheer of joy, a comment or a suggestion, feel free to contact me using");
	f.WriteLine("the address below.");
	f.WriteBlankLines(1);
	f.WriteLine("                              Igor Zlatkovic (igor@stud.fh-frankfurt.de)");
	f.Close();
}

/*
 * main(),
 * Execution begins here.
 */

// Parse the command-line arguments.
for (i = 0; (i < WScript.Arguments.length) && (error == 0); i++) {
	var arg, opt;
	arg = WScript.Arguments(i);
	opt = arg.substring(0, arg.indexOf("="));
	if (opt.length == 0)
		opt = arg.substring(0, arg.indexOf(":"));
	if (opt.length > 0) {
		if (opt == "trio")
			withTrio = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "threads")
			withThreads = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "ftp")
			withFtp = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "http")
			withHttp = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "html")
			withHtml = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "c14n")
			withC14n = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "catalog")
			withCatalog = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "docb")
			withDocb = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "xpath")
			withXpath = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "xptr")
			withXptr = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "xinclude")
			withXinclude = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "iconv")
			withIconv = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "zlib")
			withZlib = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "xml_debug")
			withDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "mem_debug")
			withMemDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "schemas")
			withSchemas = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "regexps")
			withRegExps = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "debug")
			buildDebug = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "static")
			buildStatic = strToBool(arg.substring(opt.length + 1, arg.length));
		else if (opt == "prefix")
			buildPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "bindir")
			buildBinPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "libdir")
			buildLibPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "sodir")
			buildSoPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "incdir")
			buildIncPrefix = arg.substring(opt.length + 1, arg.length);
		else if (opt == "include")
			buildInclude = arg.substring(opt.length + 1, arg.length);
		else if (opt == "lib")
			buildLib = arg.substring(opt.length + 1, arg.length);
		else
			error = 1;
	} else if (i == 0) {
		if (arg == "genreadme") {
			// This command comes from the Makefile and will not be checked
			// for errors, because Makefile will always supply right the parameters.
			genReadme(WScript.Arguments(1), WScript.Arguments(2), WScript.Arguments(3));
			WScript.Quit(0);
		} else if (arg == "help") {
			usage();
			WScript.Quit(0);
		}
	} else
		error = 1;
}

// If we fail here, it is because the user supplied an unrecognised argument.
if (error != 0) {
	usage();
	WScript.Quit(error);
}

// Discover the version.
discoverVersion();
if (error != 0) {
	WScript.Echo("Version discovery failed, aborting.");
	WScript.Quit(error);
}
WScript.Echo(baseName + " version: " + verMajor + "." + verMinor + "." + verMicro);

// Configure libxml.
configureLibxml();
if (error != 0) {
	WScript.Echo("Configuration failed, aborting.");
	WScript.Quit(error);
}

// Create the makefile.
var fso = new ActiveXObject("Scripting.FileSystemObject");
fso.CopyFile(".\\Makefile.msvc", ".\\Makefile", true);
WScript.Echo("Created Makefile.");

// Display the final configuration. 
var txtOut = "\nXML processor configuration\n";
txtOut += "---------------------------\n";
txtOut += "              Trio: " + boolToStr(withTrio) + "\n";
txtOut += "     Thread safety: " + boolToStr(withThreads) + "\n";
txtOut += "        FTP client: " + boolToStr(withFtp) + "\n";
txtOut += "       HTTP client: " + boolToStr(withHttp) + "\n";
txtOut += "    HTML processor: " + boolToStr(withHtml) + "\n";
txtOut += "      C14N support: " + boolToStr(withC14n) + "\n";
txtOut += "   Catalog support: " + boolToStr(withCatalog) + "\n";
txtOut += "   DocBook support: " + boolToStr(withDocb) + "\n";
txtOut += "     XPath support: " + boolToStr(withXpath) + "\n";
txtOut += "  XPointer support: " + boolToStr(withXptr) + "\n";
txtOut += "  XInclude support: " + boolToStr(withXinclude) + "\n";
txtOut += "     iconv support: " + boolToStr(withIconv) + "\n";
txtOut += "      zlib support: " + boolToStr(withZlib) + "\n";
txtOut += "  Debugging module: " + boolToStr(withDebug) + "\n";
txtOut += "  Memory debugging: " + boolToStr(withMemDebug) + "\n";
txtOut += "    Regexp support: " + boolToStr(withRegExps) + "\n";
txtOut += "XML Schema support: " + boolToStr(withSchemas) + "\n";
txtOut += "\n";
txtOut += "Win32 build configuration\n";
txtOut += "-------------------------\n";
txtOut += "     Debug symbols: " + boolToStr(buildDebug) + "\n";
txtOut += "    Static xmllint: " + boolToStr(buildStatic) + "\n";
txtOut += "    Install prefix: " + buildPrefix + "\n";
txtOut += "      Put tools in: " + buildBinPrefix + "\n";
txtOut += "    Put headers in: " + buildIncPrefix + "\n";
txtOut += "Put static libs in: " + buildLibPrefix + "\n";
txtOut += "Put shared libs in: " + buildSoPrefix + "\n";
txtOut += "      Include path: " + buildInclude + "\n";
txtOut += "          Lib path: " + buildLib + "\n";
WScript.Echo(txtOut);

// Done.
