#!/usr/bin/env python

#
# This is the MS subset of the W3C test suite for XML Schemas.
# This file is generated from the MS W3c test suite description file.
#

import sys, os
import exceptions, optparse
import libxml2

opa = optparse.OptionParser()

opa.add_option("-b", "--base", action="store", type="string", dest="baseDir",
               default="",
               help="""The base directory; i.e. the parent folder of the
               "nisttest", "suntest" and "msxsdtest" directories.""")

opa.add_option("-o", "--out", action="store", type="string", dest="logFile",
               default="test.log",
               help="The filepath of the log file to be created")
               
opa.add_option("--no-log", action="store_true", dest="disableLog",
               default=False,
               help="The filepath of the log file to be created")    
               
opa.add_option("--no-test-out", action="store_true", dest="disableTestStdOut",
               default=False,
               help="The filepath of the log file to be created")                           

opa.add_option("-s", "--silent", action="store_true", dest="silent", default=False,
               help="Disables display of all tests")

opa.add_option("-v", "--verbose", action="store_true", dest="verbose",
               default=False,
               help="Displays all tests (only if --silent is not set)")

opa.add_option("-x", "--max", type="int", dest="maxTestCount",
               default="-1",
               help="The maximum number of tests to be run")

opa.add_option("-t", "--test", type="string", dest="singleTest",
               default=None,
               help="Runs the specified test only")
               
opa.add_option("--rieo", "--report-internal-errors-only", action="store_true",
               dest="reportInternalErrOnly", default=False,
               help="Display erroneous tests of type 'internal' only")
               
opa.add_option("--rmleo", "--report-mem-leak-errors-only", action="store_true",
               dest="reportMemLeakErrOnly", default=False,
               help="Display erroneous tests of type 'memory leak' only")

opa.add_option("-c", "--combines", type="string", dest="combines",
               default=None,
               help="Combines to be run (all if omitted)")

opa.add_option("--rc", "--report-combines", action="store_true",
               dest="reportCombines", default=False,
               help="Display combine reports")

opa.add_option("--rec", "--report-err-combines", action="store_true",
               dest="reportErrCombines", default=False,
               help="Display erroneous combine reports only")

opa.add_option("--debug", action="store_true",
               dest="debugEnabled", default=False,
               help="Displays debug messages")
               
opa.add_option("--info", action="store_true",
               dest="info", default=False,
               help="Displays info on the suite only. Does not run any test.")            

(options, args) = opa.parse_args()

if options.combines is not None:
    options.combines = options.combines.split()
    
################################################
# The vars below are not intended to be changed.
#

msgSchemaNotValidButShould =  "The schema should be valid."
msgSchemaValidButShouldNot = "The schema should be invalid."
msgInstanceNotValidButShould = "The instance should be valid."
msgInstanceValidButShouldNot = "The instance should be invalid."
testFolderNIST = "nisttest"
testFolderMS   = "msxsdtest"
testFolderSUN  = "suntest"

###################
# Helper functions.
#

def handleError(test, msg):
    test.addLibLog("'%s'   LIB: %s" % (test.name, msg))
    if msg.find("Unimplemented") > -1:
        test.failUnimplemented()
    elif msg.find("Internal") > -1:
        test.failInternal()        
    

##################
# Test case class.
#

class MSTestCase:
           
    def __init__(self, name, descr, tFolder, sFolder, sFile, sVal, iExists, iFolder, iFile, iVal):
        global testFolderNIST, testFolderSUN, testFolderMS
        #
        # Init.
        #
        self.name = name
        self.descr = descr
        self.test_Folder = tFolder
        self.schema_Folder = sFolder
        self.schema_File = sFile
        self.schema_Val = sVal
        self.instance_Exists = iExists
        self.instance_Folder = iFolder
        self.instance_File = iFile
        self.instance_Val = iVal
        self.failed = False
        self.log = []
        self.libLog = []
        self.phase = ""
        self.initialMemUsed = 0
        self.memLeak = 0
        self.excepted = False
        self.bad = False
        self.unimplemented = False
        self.internalErr = False
        #
        # Compute combine name of this test.
        #       
        if self.test_Folder == testFolderMS or self.test_Folder == testFolderSUN:
            #
            # Use the last given directory for the combine name.
            #
            dirs = self.schema_Folder.split("/")
            self.combineName = dirs[len(dirs) -1]
	    if self.test_Folder == testFolderMS:
	        if self.combineName == "group":		    
	            self.schema_Folder = "Group"
		    self.instance_Folder = "Group"
        elif self.test_Folder == testFolderNIST:
            #
            # NIST files are named in the following form: 
            # "NISTSchema-short-pattern-1.xsd"
            #
            tokens = self.schema_File.split("-")
            self.combineName = tokens[1]            
        else:
            self.combineName = "unkown"
            raise Exception("Could not compute the combine name of a test.")
        #
        # Init the log.
        #
        self.log.append("'%s'   descr: %s\n" % (self.name, self.descr))
        self.log.append("'%s'   exp schema   valid: %d\n" % (self.name, self.schema_Val))
        if (self.instance_Exists):
            self.log.append("'%s'   exp instance valid: %d\n" % (self.name, self.instance_Val))                       
       
    def addLibLog(self, msg):
        """This one is intended to be used by the error handler
        function"""
        self.libLog.append(msg)

    def fail(self, msg):       
        self.failed = True         
        self.log.append("'%s' ( FAILED: %s\n" % (self.name, msg))
        
    def failInternal(self):
        self.failed = True
        self.internalErr = True
        self.log.append("'%s' * INTERNAL\n" % self.name)
        
    def failUnimplemented(self):
        self.failed = True
        self.unimplemented = True
        self.log.append("'%s' ? UNIMPLEMENTED\n" % self.name)

    def failCritical(self, msg):        
        self.failed = True
        self.bad = True
        self.log.append("'%s' ! BAD: %s\n" % (self.name, msg))  

    def failExcept(self, e):      
        self.failed = True
        self.excepted = True
        self.log.append("'%s' # EXCEPTION: %s\n" % (self.name, e.__str__()))
    
    def setUp(self):            
        #
        # Set up Libxml2.
        #   
        self.initialMemUsed = libxml2.debugMemory(1)
        libxml2.initParser()
        libxml2.lineNumbersDefault(1)
        libxml2.registerErrorHandler(handleError, self)
        
    def tearDown(self):        
        libxml2.schemaCleanupTypes()
        libxml2.cleanupParser()      
        self.memLeak = libxml2.debugMemory(1) - self.initialMemUsed

    def isIOError(self, file, docType):
        err = None
        try:
            err = libxml2.lastError()
        except:
            # Suppress exceptions.
            pass
        if (err is None):
            return False
        if err.domain() == libxml2.XML_FROM_IO:
            self.failCritical("failed to access the %s resource '%s'\n" % (docType, file))

    def debugMsg(self, msg):
        global options 
        if options.debugEnabled:
            sys.stdout.write("'%s'   DEBUG: %s\n" % (self.name, msg))
            
    def finalize(self):
        """Adds additional info to the log."""
        #
        # Add libxml2 messages.
        #
        self.log.extend(self.libLog)
        #
        # Add memory leaks.
        #        
        if self.memLeak != 0:            
            self.log.append("%s + memory leak: %d bytes\n" % (self.name, self.memLeak))
            
    def processSchema(self, filePath):
        global msgSchemaNotValidButShould, msgSchemaValidButShouldNot
        schema = None
        
        #
        # Parse the schema.
        #
        self.debugMsg("loading schema: %s" % filePath)
        schema_ParserCtxt = libxml2.schemaNewParserCtxt(filePath)
        try:
            try:
                schema = schema_ParserCtxt.schemaParse()
            except:
                pass
        finally:
            self.debugMsg("after loading schema")
            del schema_ParserCtxt
        if schema is None:
            self.debugMsg("schema is None")
            self.debugMsg("checking for IO errors...")
            if self.isIOError(file, "schema"):
                return None
        self.debugMsg("checking schema result")
        if (schema is None and self.schema_Val) or (schema is not None and self.schema_Val == 0):
            self.debugMsg("schema result is BAD")
            if (schema == None):
                self.fail(msgSchemaNotValidButShould)
            else:
                self.fail(msgSchemaValidButShouldNot)
        else:
	    self.debugMsg("schema result is OK")
            return schema

    def processInstance(self, filePath, schema):
        global msgInstanceNotValidButShould, msgInstanceValidButShouldNot
        
        instance = None
        self.debugMsg("loading instance: %s" % filePath)            
        instance_parserCtxt = libxml2.newParserCtxt()
        if (instance_parserCtxt is None):
            # TODO: Is this one necessary, or will an exception 
            # be already raised?
            raise Exception("Could not create the instance parser context.")
        try:
            try:
                instance = instance_parserCtxt.ctxtReadFile(filePath, None, libxml2.XML_PARSE_NOWARNING)
            except:
                # Suppress exceptions.
                pass
        finally:
            del instance_parserCtxt
        self.debugMsg("after loading instance")
        if instance is None:
            self.debugMsg("instance is None")
            self.failCritical("Failed to parse the instance for unknown reasons.")
            return
        else:
            try:
                #
                # Validate the instance.
                #
		
                validation_Ctxt = schema.schemaNewValidCtxt()
		#validation_Ctxt = libxml2.schemaNewValidCtxt(None)
                if (validation_Ctxt is None):
                    self.failCritical("Could not create the validation context.")
                    return
                try:
                    self.debugMsg("validating instance") 
                    instance_Err = validation_Ctxt.schemaValidateDoc(instance)
                    self.debugMsg("after instance validation") 
                    self.debugMsg("instance-err: %d" % instance_Err)
                    if (instance_Err != 0 and self.instance_Val == 1) or (instance_Err == 0 and self.instance_Val == 0):
                        self.debugMsg("instance result is BAD")
                        if (instance_Err != 0):
                            self.fail(msgInstanceNotValidButShould)
                        else:
                            self.fail(msgInstanceValidButShouldNot)
                            
                    else:                        
                                self.debugMsg("instance result is OK")
                finally:
                    del validation_Ctxt
            finally:
                instance.freeDoc()
            

    def run(self):
        """Runs a test.""" 
        global options
        
        # os.path.join(options.baseDir, self.test_Folder, self.schema_Folder, self.schema_File)
        filePath = "%s/%s/%s/%s" % (options.baseDir, self.test_Folder, self.schema_Folder, self.schema_File)
        schema = None
        try:                
            schema = self.processSchema(filePath)
            try:
                if self.instance_Exists and (schema is not None) and (not self.failed):
                    filePath = "%s/%s/%s/%s" % (options.baseDir, self.test_Folder, self.instance_Folder, self.instance_File)
                    self.processInstance(filePath, schema)
            finally:
                if schema is not None:
                   del schema

        except (Exception, libxml2.parserError, libxml2.treeError), e:
            self.failExcept(e)

            
####################
# Test runner class.
#
              
class MSTestRunner:

    CNT_TOTAL = 0
    CNT_RAN = 1
    CNT_SUCCEEDED = 2
    CNT_FAILED = 3
    CNT_UNIMPLEMENTED = 4
    CNT_INTERNAL = 5
    CNT_BAD = 6
    CNT_EXCEPTED = 7
    CNT_MEMLEAK = 8

    def __init__(self):
        self.logFile = None
        self.counters = self.createCounters()
        self.testList = []
        self.combinesRan = {}
        
    def createCounters(self):
        counters = {self.CNT_TOTAL:0, self.CNT_RAN:0, self.CNT_SUCCEEDED:0,
        self.CNT_FAILED:0, self.CNT_UNIMPLEMENTED:0, self.CNT_INTERNAL:0, self.CNT_BAD:0, 
        self.CNT_EXCEPTED:0, self.CNT_MEMLEAK:0}
        
        return counters

    def addTest(self, test):
        self.testList.append(test)
        
    def updateCounters(self, test, counters):
        if test.memLeak != 0:
           counters[self.CNT_MEMLEAK] += 1
        if not test.failed:
           counters[self.CNT_SUCCEEDED] +=1
        if test.failed:
           counters[self.CNT_FAILED] += 1
        if test.bad:
           counters[self.CNT_BAD] += 1
        if test.unimplemented:
           counters[self.CNT_UNIMPLEMENTED] += 1   
        if test.internalErr:
           counters[self.CNT_INTERNAL] += 1                      
        if test.excepted:
           counters[self.CNT_EXCEPTED] += 1
        return counters
           
    def displayResults(self, out, all, combName, counters):
        out.write("\n")
        if all:
            if options.combines is not None:
                out.write("combine(s): %s\n" % str(options.combines))
        elif combName is not None:             
            out.write("combine : %s\n" % combName)
        out.write("  total             : %d\n" % counters[self.CNT_TOTAL])
        if all or options.combines is not None:
            out.write("    ran             : %d\n" % counters[self.CNT_RAN])
        # out.write("    succeeded       : %d\n" % counters[self.CNT_SUCCEEDED])
        if counters[self.CNT_FAILED] > 0:
            out.write("    failed          : %d\n" % counters[self.CNT_FAILED])
            out.write("     -> internal    : %d\n" % counters[self.CNT_INTERNAL])
            out.write("     -> unimpl.     : %d\n" % counters[self.CNT_UNIMPLEMENTED])
            out.write("     -> bad         : %d\n" % counters[self.CNT_BAD])            
            out.write("     -> exceptions  : %d\n" % counters[self.CNT_EXCEPTED])
        if counters[self.CNT_MEMLEAK] > 0:
            out.write("    memory leaks    : %d\n" % counters[self.CNT_MEMLEAK])

    def displayShortResults(self, out, all, combName, counters):
        out.write("Ran %d of %d tests:" % (counters[self.CNT_RAN],
                  counters[self.CNT_TOTAL]))
        # out.write("    succeeded       : %d\n" % counters[self.CNT_SUCCEEDED])
        if counters[self.CNT_FAILED] > 0 or counters[self.CNT_MEMLEAK] > 0:
            out.write(" %d failed" % (counters[self.CNT_FAILED]))
            if counters[self.CNT_INTERNAL] > 0:
                out.write(" %d internal" % (counters[self.CNT_INTERNAL]))
            if counters[self.CNT_UNIMPLEMENTED] > 0:
                out.write(" %d unimplemented" % (counters[self.CNT_UNIMPLEMENTED]))
            if counters[self.CNT_BAD] > 0:
                out.write(" %d bad" % (counters[self.CNT_BAD]))
            if counters[self.CNT_EXCEPTED] > 0:
                out.write(" %d exception" % (counters[self.CNT_EXCEPTED]))
            if counters[self.CNT_MEMLEAK] > 0:
                out.write(" %d leaks" % (counters[self.CNT_MEMLEAK]))
            out.write("\n")
        else:
            out.write(" all passed\n")
    
    def reportCombine(self, combName):
        global options
        
        counters = self.createCounters()
        #
        # Compute evaluation counters.
        #
        for test in self.combinesRan[combName]:
            counters[self.CNT_TOTAL] += 1
            counters[self.CNT_RAN] += 1
            counters = self.updateCounters(test, counters)
        if options.reportErrCombines and (counters[self.CNT_FAILED] == 0) and (counters[self.CNT_MEMLEAK] == 0):
            pass
        else:
            if not options.disableLog:
                self.displayResults(self.logFile, False, combName, counters)
            self.displayResults(sys.stdout, False, combName, counters)
        
    def displayTestLog(self, test):
        sys.stdout.writelines(test.log)
        sys.stdout.write("~~~~~~~~~~\n")
    
    def reportTest(self, test):
        global options
        
        error = test.failed or test.memLeak != 0
        #
        # Only erroneous tests will be written to the log,
        # except @verbose is switched on.
        #        
        if not options.disableLog and (options.verbose or error):
            self.logFile.writelines(test.log)
            self.logFile.write("~~~~~~~~~~\n")
        #
        # if not @silent, only erroneous tests will be
        # written to stdout, except @verbose is switched on.
        #
        if not options.silent: 
            if options.reportInternalErrOnly and test.internalErr:
                self.displayTestLog(test)
            if options.reportMemLeakErrOnly and test.memLeak != 0: 
                self.displayTestLog(test)
            if (options.verbose or error) and (not options.reportInternalErrOnly) and (not options.reportMemLeakErrOnly):
                self.displayTestLog(test)
                
    def addToCombines(self, test):
        found = False
        if self.combinesRan.has_key(test.combineName):
            self.combinesRan[test.combineName].append(test)
        else:
            self.combinesRan[test.combineName] = [test]

    def run(self):

        global options
        
        if options.info:
            for test in self.testList:
                self.addToCombines(test)               
            sys.stdout.write("Combines: %d\n" % len(self.combinesRan))
            sys.stdout.write("%s\n" % self.combinesRan.keys())
            return
        
        if not options.disableLog:
            self.logFile = open(options.logFile, "w")
        try:
            for test in self.testList:
                self.counters[self.CNT_TOTAL] += 1
                #
                # Filter tests.
                #   
                if options.singleTest is not None and options.singleTest != "":
                    if (test.name != options.singleTest):
                        continue
                elif options.combines is not None:
                    if not options.combines.__contains__(test.combineName):
                        continue
                if options.maxTestCount != -1 and self.counters[self.CNT_RAN] >= options.maxTestCount:
                    break
                self.counters[self.CNT_RAN] += 1
                #
                # Run the thing, dammit.
                #
                try:
                    test.setUp()
                    try:
                        test.run()
                    finally:
                        test.tearDown()
                finally:
                    #
                    # Evaluate.
                    #
                    test.finalize()
                    self.reportTest(test)
                    if options.reportCombines or options.reportErrCombines:
                        self.addToCombines(test)
                    self.counters = self.updateCounters(test, self.counters)
        finally:        
            if options.reportCombines or options.reportErrCombines:
                #
                # Build a report for every single combine.
                #
                # TODO: How to sort a dict?
                #
                self.combinesRan.keys().sort(None)
                for key in self.combinesRan.keys():
                    self.reportCombine(key)
            
            #
            # Display the final report.
            #
            if options.silent:
                self.displayShortResults(sys.stdout, True, None, self.counters)
            else:
                sys.stdout.write("===========================\n")
                self.displayResults(sys.stdout, True, None, self.counters)
