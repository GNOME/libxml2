/*
 * xmlcatalog.c : a small utility program to handle XML catalogs
 *
 * See Copyright for the status of this software.
 *
 * daniel@veillard.com
 */

#include "libxml.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#ifdef HAVE_LIBHISTORY
#include <readline/history.h>
#endif
#endif

#include <libxml/xmlmemory.h>
#include <libxml/uri.h>
#include <libxml/catalog.h>
#include <libxml/parser.h>

static int shell = 0;
static int noout = 0;
static int verbose = 0;

#ifdef LIBXML_CATALOG_ENABLED
/************************************************************************
 * 									*
 * 			Shell Interface					*
 * 									*
 ************************************************************************/
/**
 * xmlShellReadline:
 * @prompt:  the prompt value
 *
 * Read a string
 * 
 * Returns a pointer to it or NULL on EOF the caller is expected to
 *     free the returned string.
 */
static char *
xmlShellReadline(const char *prompt) {
#ifdef HAVE_LIBREADLINE
    char *line_read;

    /* Get a line from the user. */
    line_read = readline (prompt);

    /* If the line has any text in it, save it on the history. */
    if (line_read && *line_read)
	add_history (line_read);

    return (line_read);
#else
    char line_read[501];

    if (prompt != NULL)
	fprintf(stdout, "%s", prompt);
    if (!fgets(line_read, 500, stdin))
        return(NULL);
    line_read[500] = 0;
    return(strdup(line_read));
#endif
}


static void usershell(void) {
    char *cmdline = NULL, *cur;
    int nbargs;
    char command[100];
    char arg[400];
    int i;
    const xmlChar *answer;

    while (1) {
	cmdline = xmlShellReadline("> ");
	if (cmdline == NULL)
	    return;

	/*
	 * Parse the command itself
	 */
	cur = cmdline;
	nbargs = 0;
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	i = 0;
	while ((*cur != ' ') && (*cur != '\t') &&
	       (*cur != '\n') && (*cur != '\r')) {
	    if (*cur == 0)
		break;
	    command[i++] = *cur++;
	}
	command[i] = 0;
	if (i == 0) continue;
	nbargs++;

	/*
	 * Parse the argument
	 */
	while ((*cur == ' ') || (*cur == '\t')) cur++;
	i = 0;
	while ((*cur != '\n') && (*cur != '\r') && (*cur != 0)) {
	    if (*cur == 0)
		break;
	    arg[i++] = *cur++;
	}
	arg[i] = 0;
	if (i != 0) 
	    nbargs++;

	/*
	 * start interpreting the command
	 */
        if (!strcmp(command, "exit"))
	    break;
        if (!strcmp(command, "quit"))
	    break;
        if (!strcmp(command, "bye"))
	    break;
	if (!strcmp(command, "public")) {
	    answer = xmlCatalogGetPublic((const xmlChar *) arg);
	    if (answer == NULL) {
		printf("No entry for PUBLIC %s\n", arg);
	    } else {
		printf("%s\n", answer);
	    }
	} else if (!strcmp(command, "system")) {
	    answer = xmlCatalogGetSystem((const xmlChar *) arg);
	    if (answer == NULL) {
		printf("No entry for SYSTEM %s\n", arg);
	    } else {
		printf("%s\n", answer);
	    }
	} else if (!strcmp(command, "dump")) {
	    xmlCatalogDump(stdout);
	} else {
	    if (strcmp(command, "help")) {
		printf("Unrecognized command %s\n", command);
	    }
	    printf("Commands available:\n");
	    printf("\tpublic PublicID: make a PUBLIC identifier lookup\n");
	    printf("\tsystem SystemID: make a SYSTEM identifier lookup\n");
	    printf("\tdump: print the current catalog state\n");
	    printf("\texit:  quit the shell\n");
	} 
	free(cmdline); /* not xmlFree here ! */
    }
}

/************************************************************************
 * 									*
 * 			Main						*
 * 									*
 ************************************************************************/
static void usage(const char *name) {
    printf("Usage : %s [options] catalogfile ...\n", name);
    printf("\tParse the catalog file(s) and output the result of the parsing\n");
    printf("\t--shell : run a shell allowing interactive queries\n");
    printf("\t-v --verbose : provide debug informations\n");
}
int main(int argc, char **argv) {
    int i;

    if (argc <= 1) {
	usage(argv[0]);
	return(1);
    }

    LIBXML_TEST_VERSION
    for (i = 1; i < argc ; i++) {
	if (!strcmp(argv[i], "-"))
	    break;

	if (argv[i][0] != '-')
	    continue;
	if ((!strcmp(argv[i], "-verbose")) ||
	    (!strcmp(argv[i], "-v")) ||
	    (!strcmp(argv[i], "--verbose"))) {
	    verbose++;
	    xmlCatalogSetDebug(verbose);
	} else if ((!strcmp(argv[i], "-shell")) ||
	    (!strcmp(argv[i], "--shell"))) {
	    shell++;
            noout = 1;
	} else {
	    fprintf(stderr, "Unknown option %s\n", argv[i]);
	    usage(argv[0]);
	    return(1);
	}
    }

    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-')
	    continue;
	xmlLoadCatalog(argv[i]);
    }

    if (shell) {
	usershell();
    }
    if (!noout) {
	xmlCatalogDump(stdout);
    }

    /*
     * Cleanup and check for memory leaks
     */
    xmlCatalogCleanup();
    xmlCleanupParser();
    xmlMemoryDump();
    return(0);
}
#else
int main(int argc, char **argv) {
    fprintf(stderr, "libxml was not compiled with catalog support\n");
    return(1);
}
#endif
