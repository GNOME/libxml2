/*
 * testOOM.c: Test out-of-memory handling
 *
 * See Copyright for the status of this software.
 *
 * hp@redhat.com
 */

/* FIXME this test would be much better if instead of just checking
 * for debug spew or crashes on OOM, it also validated the expected
 * results of parsing a particular file vs. the actual results
 */

#include "libxml.h"

#include <string.h>
#include <stdarg.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <libxml/xmlreader.h>

#include "testOOMlib.h"

#ifndef TRUE
#define TRUE (1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif


int debug = 0;
int dump = 0;
int noent = 0;
int count = 0;
int valid = 0;

static void usage(const char *progname) {
    printf("Usage : %s [options] XMLfiles ...\n", progname);
    printf("\tParse the XML files using the xmlTextReader API\n");
    printf("\t --count: count the number of attribute and elements\n");
    printf("\t --valid: validate the document\n");
    exit(1);
}
static int elem, attrs;

static int processNode(xmlTextReaderPtr reader) {
    int type;

    type = xmlTextReaderNodeType(reader);
    if (count) {
	if (type == 1) {
	    elem++;
	    attrs += xmlTextReaderAttributeCount(reader);
	}
    }

    return TRUE;
}

/* This always returns TRUE since we don't validate the results of
 * parsing a particular document vs. the expected results of parsing
 * that document. The idea is that such a failure would return FALSE.
 */
static int
check_load_file_memory_func (void *data)
{
     const char *filename = data;
     xmlTextReaderPtr reader;
     int ret;

     if (count) {
          elem = 0;
          attrs = 0;
     }

     reader = xmlNewTextReaderFilename(filename);
     
     if (reader != NULL) {
          if (valid) {
               if (xmlTextReaderSetParserProp(reader, XML_PARSER_VALIDATE, 1) == -1) {
                    xmlFreeTextReader (reader);
                    return TRUE;
               }
          }
          
          /*
           * Process all nodes in sequence
           */
          ret = xmlTextReaderRead (reader);
          
          while (TRUE) {
               if (ret == -1) {
                    xmlFreeTextReader (reader);
                    return TRUE;
               } else if (ret != 1)
                    break;
               
               if (!processNode(reader)) {
                    xmlFreeTextReader (reader);
                    return FALSE;
               }
               
               ret = xmlTextReaderRead(reader);
          }

          /*
           * Done, cleanup and status
           */
          xmlFreeTextReader (reader);

          return TRUE;
     } else {
          return TRUE;
     }
}

int main(int argc, char **argv) {
    int i;
    int files = 0;

    if (argc <= 1) {
	usage(argv[0]);
	return(1);
    }
    LIBXML_TEST_VERSION;      

    xmlMemSetup (test_free,
                 test_malloc,
                 test_realloc,
                 test_strdup);
    
    for (i = 1; i < argc ; i++) {
	if ((!strcmp(argv[i], "-debug")) || (!strcmp(argv[i], "--debug")))
	    debug++;
	else if ((!strcmp(argv[i], "-dump")) || (!strcmp(argv[i], "--dump")))
	    dump++;
	else if ((!strcmp(argv[i], "-count")) || (!strcmp(argv[i], "--count")))
	    count++;
	else if ((!strcmp(argv[i], "-valid")) || (!strcmp(argv[i], "--valid")))
	    valid++;
	else if ((!strcmp(argv[i], "-noent")) ||
	         (!strcmp(argv[i], "--noent")))
	    noent++;
    }
    if (noent != 0)
      xmlSubstituteEntitiesDefault(1);
    for (i = 1; i < argc ; i++) {
	if (argv[i][0] != '-') {
             if (!test_oom_handling (check_load_file_memory_func,
                                     argv[i])) {
                  fprintf (stderr, "Failed!\n");
                  return (1);
             }

             xmlCleanupParser();

             if (test_get_malloc_blocks_outstanding () > 0) {
                  fprintf (stderr, "%d blocks leaked\n",
                           test_get_malloc_blocks_outstanding ());
		  xmlMemoryDump();
                  return (1);
             }
             
	    files ++;
	}
    }
    xmlMemoryDump();

    return(0);
}
