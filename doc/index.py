#!/usr/bin/python -u
#
# imports the API description and fills up a database with
# name relevance to modules, functions or web pages
#
import MySQLdb
import libxml2
import sys
import string
import os

#
# The dictionnary of tables required and the SQL command needed
# to create them
#
TABLES={
  "symbols" : """CREATE TABLE symbols (
           name varchar(255) NOT NULL,
	   module varchar(255) NOT NULL,
           type varchar(25) NOT NULL,
	   descr varchar(255),
	   UNIQUE KEY name (name),
	   KEY module (module))""",
  "words" : """CREATE TABLE words (
           name varchar(50) NOT NULL,
	   symbol varchar(255) NOT NULL,
           relevance int,
	   KEY name (name),
	   KEY symbol (symbol),
	   UNIQUE KEY ID (name, symbol))""",
}

#
# The XML API description file to parse
#
API="libxml2-api.xml"
DB=None

#########################################################################
#									#
#                  MySQL database interfaces				#
#									#
#########################################################################
def createTable(db, name):
    global TABLES

    if db == None:
        return -1
    if name == None:
        return -1
    c = db.cursor()

    ret = c.execute("DROP TABLE IF EXISTS %s" % (name))
    if ret == 1:
        print "Removed table %s" % (name)
    print "Creating table %s" % (name)
    try:
        ret = c.execute(TABLES[name])
    except:
        print "Failed to create table %s" % (name)
	return -1
    return ret

def checkTables(db):
    global TABLES

    if db == None:
        return -1
    c = db.cursor()
    nbtables = c.execute("show tables")
    print "Found %d tables" % (nbtables)
    tables = {}
    i = 0
    while i < nbtables:
        l = c.fetchone()
	name = l[0]
	tables[name] = {}
        i = i + 1

    for table in TABLES.keys():
        if not tables.has_key(table):
	    print "table %s missing" % (table)
	    createTable(db, table)
    print "checkTables finished"

    # make sure apache can access the tables read-only
    try:
	ret = c.execute("GRANT SELECT ON xmlsoft.* TO nobody@localhost")
    except:
        pass
    return 0
    
def openMySQL(db="xmlsoft", passwd=None):
    global DB

    if passwd == None:
        passwd = "ducon"
    DB = MySQLdb.connect(passwd=passwd, db=db)
    if DB == None:
        return -1
    ret = checkTables(DB)
    return ret

def updateWord(name, symbol, relevance):
    global DB

    if DB == None:
        openMySQL()
    if DB == None:
        return -1
    if name == None:
        return -1
    if symbol == None:
        return -1

    c = DB.cursor()
    try:
	ret = c.execute(
"""INSERT INTO words (name, symbol, relevance) VALUES ('%s','%s', %d)""" %
		(name, symbol, relevance))
    except:
        try:
	    ret = c.execute(
    """UPDATE words SET relevance = %d where name = '%s' and symbol = '%s'""" %
		    (relevance, name, symbol))
	except:
	    print "Update word (%s, %s, %s) failed command" % (name, symbol, relevance)
	    print "UPDATE words SET relevance = %d where name = '%s' and symbol = '%s'" % (relevance, name, symbol)
	    print sys.exc_type, sys.exc_value
	    return -1
	     
    return ret

def updateSymbol(name, module, type, desc):
    global DB

    updateWord(name, name, 50)
    if DB == None:
        openMySQL()
    if DB == None:
        return -1
    if name == None:
        return -1
    if module == None:
        return -1
    if type == None:
        return -1

    try:
	desc = string.replace(desc, "'", " ")
	l = string.split(desc, ".")
	desc = l[0]
	desc = desc[0:99]
    except:
        desc = ""

    c = DB.cursor()
    try:
	ret = c.execute(
"""INSERT INTO symbols (name, module, type, descr) VALUES ('%s','%s', '%s', '%s')""" %
                    (name, module, type, desc))
    except:
        try:
	    ret = c.execute(
"""UPDATE symbols SET module='%s', type='%s', descr='%s' where name='%s'""" %
                    (module, type, desc, name))
        except:
	    print "Update symbol (%s, %s, %s) failed command" % (name, module, type)
	    print """UPDATE symbols SET module='%s', type='%s', descr='%s' where name='%s'""" % (module, type, desc, name)
	    print sys.exc_type, sys.exc_value
	    return -1
	     
    return ret
        
def addFunction(name, module, desc = ""):
    return updateSymbol(name, module, 'function', desc)

def addMacro(name, module, desc = ""):
    return updateSymbol(name, module, 'macro', desc)

def addEnum(name, module, desc = ""):
    return updateSymbol(name, module, 'enum', desc)

def addStruct(name, module, desc = ""):
    return updateSymbol(name, module, 'struct', desc)

def addConst(name, module, desc = ""):
    return updateSymbol(name, module, 'const', desc)

def addType(name, module, desc = ""):
    return updateSymbol(name, module, 'type', desc)

def addFunctype(name, module, desc = ""):
    return updateSymbol(name, module, 'functype', desc)

#########################################################################
#									#
#                  Word dictionnary and analysis routines		#
#									#
#########################################################################

wordsDict = {}

def splitIdentifier(str):
    ret = []
    while str != "":
        cur = string.lower(str[0])
	str = str[1:]
	if ((cur < 'a') or (cur > 'z')):
	    continue
	while (str != "") and (str[0] >= 'A') and (str[0] <= 'Z'):
	    cur = cur + string.lower(str[0])
	    str = str[1:]
	while (str != "") and (str[0] >= 'a') and (str[0] <= 'z'):
	    cur = cur + str[0]
	    str = str[1:]
	while (str != "") and (str[0] >= '0') and (str[0] <= '9'):
	    str = str[1:]
	ret.append(cur)
    return ret

def addWord(word, module, symbol, relevance):
    global wordsDict

    if word == None or len(word) < 3:
        return -1
    if module == None or symbol == None:
        return -1
    if wordsDict.has_key(word):
        d = wordsDict[word]
	if d == None:
	    return 0
	if len(d) > 500:
	    wordsDict[word] = None
	    return 0
	try:
	    relevance = relevance + d[(module, symbol)]
	except:
	    pass
    else:
        wordsDict[word] = {}
    wordsDict[word][(module, symbol)] = relevance
    return relevance
    
def addString(str, module, symbol, relevance):
    if str == None or len(str) < 3:
        return -1
    ret = 0
    str = string.replace(str, ".", " ")
    str = string.replace(str, ",", " ")
    str = string.replace(str, "'", " ")
    str = string.replace(str, '"', " ")
    str = string.replace(str, ";", " ")
    str = string.replace(str, "-", " ")
    l = string.split(str)
    for word in l:
	if len(word) > 2:
	    ret = ret + addWord(word, module, symbol, 5)

    return ret


#########################################################################
#									#
#                  XML API description analysis				#
#									#
#########################################################################

def loadAPI(filename):
    doc = libxml2.parseFile(filename)
    print "loaded %s" % (filename)
    return doc

def foundExport(file, symbol):
    if file == None:
        return 0
    if symbol == None:
        return 0
    addFunction(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)
    return 1
     
def analyzeAPIFile(top):
    count = 0
    name = top.prop("name")
    cur = top.children
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "exports":
	    count = count + foundExport(name, cur.prop("symbol"))
	else:
	    print "unexpected element %s in API doc <file name='%s'>" % (name)
        cur = cur.next
    return count

def analyzeAPIFiles(top):
    count = 0
    cur = top.children
        
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "file":
	    count = count + analyzeAPIFile(cur)
	else:
	    print "unexpected element %s in API doc <files>" % (cur.name)
        cur = cur.next
    return count

def analyzeAPIEnum(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    addEnum(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)

    return 1

def analyzeAPIConst(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    addConst(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)

    return 1

def analyzeAPIType(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    addType(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)
    return 1

def analyzeAPIFunctype(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    addFunctype(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)
    return 1

def analyzeAPIStruct(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    addStruct(symbol, file)
    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)

    info = top.prop("info")
    if info != None:
	l = string.split(info)
	for word in l:
	    if len(word) > 2:
		addWord(word, file, symbol, 5)
    return 1

def analyzeAPIMacro(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    info = None
    cur = top.children
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "info":
	    info = cur.content
	    break
        cur = cur.next

    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)

    if info == None:
	addMacro(symbol, file)
        print "Macro %s description has no <info>" % (symbol)
        return 0

    addMacro(symbol, file, info)
    l = string.split(info)
    for word in l:
	if len(word) > 2:
	    addWord(word, file, symbol, 5)
    return 1

def analyzeAPIFunction(top):
    file = top.prop("file")
    if file == None:
        return 0
    symbol = top.prop("name")
    if symbol == None:
        return 0

    info = None
    cur = top.children
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "info":
	    info = cur.content
	elif cur.name == "return":
	    rinfo = cur.prop("info")
	    if rinfo != None:
	        addString(rinfo, file, symbol, 7)
	elif cur.name == "arg":
	    ainfo = cur.prop("info")
	    if rinfo != None:
	        addString(ainfo, file, symbol, 5)
	    name = cur.prop("name")
	    if name != None:
	        addWord(name, file, symbol, 7)
        cur = cur.next
    if info == None:
        print "Function %s description has no <info>" % (symbol)
	addFunction(symbol, file, "")
    else:
	addFunction(symbol, file, info)
        addString(info, file, symbol, 5)

    l = splitIdentifier(symbol)
    for word in l:
	addWord(word, file, symbol, 10)

    return 1

def analyzeAPISymbols(top):
    count = 0
    cur = top.children
        
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "macro":
	    count = count + analyzeAPIMacro(cur)
	elif cur.name == "function":
	    count = count + analyzeAPIFunction(cur)
	elif cur.name == "const":
	    count = count + analyzeAPIConst(cur)
	elif cur.name == "typedef":
	    count = count + analyzeAPIType(cur)
	elif cur.name == "struct":
	    count = count + analyzeAPIStruct(cur)
	elif cur.name == "enum":
	    count = count + analyzeAPIEnum(cur)
	elif cur.name == "functype":
	    count = count + analyzeAPIFunctype(cur)
	else:
	    print "unexpected element %s in API doc <files>" % (cur.name)
        cur = cur.next
    return count

def analyzeAPI(doc):
    count = 0
    if doc == None:
        return -1
    root = doc.getRootElement()
    if root.name != "api":
        print "Unexpected root name"
        return -1
    cur = root.children
    while cur != None:
        if cur.type == 'text':
	    cur = cur.next
	    continue
	if cur.name == "files":
	    pass
#	    count = count + analyzeAPIFiles(cur)
	elif cur.name == "symbols":
	    count = count + analyzeAPISymbols(cur)
	else:
	    print "unexpected element %s in API doc" % (cur.name)
        cur = cur.next
    return count

#########################################################################
#									#
#          Main code: open the DB, the API XML and analyze it		#
#									#
#########################################################################
try:
    openMySQL()
except:
    print "Failed to open the database"
    print sys.exc_type, sys.exc_value
    sys.exit(1)

try:
    doc = loadAPI(API)
    ret = analyzeAPI(doc)
    print "Analyzed %d blocs" % (ret)
    doc.freeDoc()
except:
    print "Failed to parse and analyze %s" % (API)
    print sys.exc_type, sys.exc_value
    sys.exit(1)

print "Indexed %d words" % (len(wordsDict))
i = 0
skipped = 0
for word in wordsDict.keys():
    refs = wordsDict[word]
    if refs  == None:
        skipped = skipped + 1
        continue;
    for (module, symbol) in refs.keys():
        updateWord(word, symbol, refs[(module, symbol)])
	i = i + 1

print "Found %d associations, skipped %d words" % (i, skipped)
