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
static int add = 0;
static int del = 0;
static int verbose = 0;
static char *filename;

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
    char *argv[20];
    int i, ret;
    const xmlChar *answer;
    xmlChar *ans;

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
	 * Parse the argument string
	 */
	memset(arg, 0, sizeof(arg));
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
	 * Parse the arguments
	 */
	i = 0;
	nbargs = 0;
	cur = arg;
	memset(argv, 0, sizeof(argv));
	while (*cur != 0) {
	    while ((*cur == ' ') || (*cur == '\t')) cur++;
	    if (*cur == '\'') {
		cur++;
		argv[i] = cur;
		while ((*cur != 0) && (*cur != '\'')) cur++;
		if (*cur == '\'') {
		    *cur = 0;
		    nbargs++;
		    i++;
		    cur++;
		}
	    } else if (*cur == '"') { 
		cur++;
		argv[i] = cur;
		while ((*cur != 0) && (*cur != '"')) cur++;
		if (*cur == '"') {
		    *cur = 0;
		    nbargs++;
		    i++;
		    cur++;
		}
	    } else {
		argv[i] = cur;
		while ((*cur != 0) && (*cur != ' ') && (*cur != '\t'))
		    cur++;
		*cur = 0;
		nbargs++;
		i++;
		cur++;
	    }
	}

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
	    if (nbargs != 1) {
		printf("public requires 1 arguments\n");
	    } else {
		answer = xmlCatalogGetPublic((const xmlChar *) argv[0]);
		if (answer == NULL) {
		    printf("No entry for PUBLIC %s\n", argv[0]);
		} else {
		    printf("%s\n", answer);
		}
	    }
	} else if (!strcmp(command, "system")) {
	    if (nbargs != 1) {
		printf("system requires 1 arguments\n");
	    } else {
		answer = xmlCatalogGetSystem((const xmlChar *) argv[0]);
		if (answer == NULL) {
		    printf("No entry for SYSTEM %s\n", argv[0]);
		} else {
		    printf("%s\n", answer);
		}
	    }
	} else if (!strcmp(command, "add")) {
	    if ((nbargs != 3) && (nbargs != 2)) {
		printf("add requires 2 or 3 arguments\n");
	    } else {
		if (argv[2] == NULL)
		    ret = xmlCatalogAdd(BAD_CAST argv[0], NULL,
			                BAD_CAST argv[1]);
		else
		    ret = xmlCatalogAdd(BAD_CAST argv[0], BAD_CAST argv[1],
			                BAD_CAST argv[2]);
		if (ret != 0)
		    printf("add command failed\n");
	    }
	} else if (!strcmp(command, "del")) {
	    if (nbargs != 1) {
		printf("del requires 1\n");
	    } else {
		ret = xmlCatalogRemove(BAD_CAST argv[0]);
		if (ret <= 0)
		    printf("del command failed\n");

	    }
	} else if (!strcmp(command, "resolve")) {
	    if (nbargs != 2) {
		printf("resolve requires 2 arguments\n");
	    } else {
		ans = xmlCatalogResolve(BAD_CAST argv[0],
			                BAD_CAST argv[1]);
		if (ans == NULL) {
		    printf("Resolver failed to find an answer\n");
		} else {
		    printf("%s\n", ans);
		    xmlFree(ans);
		}
	    }
	} else if (!strcmp(command, "dump")) {
	    if (nbargs != 0) {
		printf("dump has no arguments\n");
	    } else {
		xmlCatalogDump(stdout);
	    }
	} else {
	    if (strcmp(command, "help")) {
		printf("Unrecognized command %s\n", command);
	    }
	    printf("Commands available:\n");
	    printf("\tpublic PublicID: make a PUBLIC identifier lookup\n");
	    printf("\tsystem SystemID: make a SYSTEM identifier lookup\n");
	    printf("\tresolve PublicID SystemID: do a full resolver lookup\n");
	    printf("\tadd 'type' 'orig' 'replace' : add an entry\n");
	    printf("\tdel 'values' : remove values\n");
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
    printf("Usage : %s [options] catalogfile\n", name);
    printf("\tParse the catalog file and output the result of the parsing\n");
    printf("\t--shell : run a shell allowing interactive queries\n");
    printf("\t--add 'type' 'orig' 'replace' : add an entry\n");
    printf("\t--del 'values' : remove values\n");
    printf("\t--noout: avoid dumping the result on stdout\n");
    printf("\t         used with add or del, it saves the catalog changes\n");
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
	} else if ((!strcmp(argv[i], "-noout")) ||
	    (!strcmp(argv[i], "--noout"))) {
            noout = 1;
	} else if ((!strcmp(argv[i], "-shell")) ||
	    (!strcmp(argv[i], "--shell"))) {
	    shell++;
            noout = 1;
	} else if ((!strcmp(argv[i], "-add")) ||
	    (!strcmp(argv[i], "--add"))) {
	    i += 3;
	    add++;
	} else if ((!strcmp(argv[i], "-del")) ||
	    (!strcmp(argv[i], "--del"))) {
	    i += 1;
	    del++;
	} else {
	    fprintf(stderr, "Unknown option %s\n", argv[i]);
	    usage(argv[0]);
	    return(1);
	}
    }

    for (i = 1; i < argc; i++) {
	if ((!strcmp(argv[i], "-add")) ||
	    (!strcmp(argv[i], "--add"))) {
	    i += 3;
	    continue;
	} else if ((!strcmp(argv[i], "-del")) ||
	    (!strcmp(argv[i], "--del"))) {
	    i += 1;
	    continue;
	} else if (argv[i][0] == '-')
	    continue;
	filename = argv[i];
	xmlLoadCatalog(argv[i]);
	break;
    }

    if ((add) || (del)) {
	int ret;

	for (i = 1; i < argc ; i++) {
	    if (!strcmp(argv[i], "-"))
		break;

	    if (argv[i][0] != '-')
		continue;
	    if ((!strcmp(argv[i], "-add")) ||
		(!strcmp(argv[i], "--add"))) {
		if ((argv[i + 3] == NULL) || (argv[i + 3][0] == 0))
		    ret = xmlCatalogAdd(BAD_CAST argv[i + 1], NULL,
			                BAD_CAST argv[i + 2]);
		else
		    ret = xmlCatalogAdd(BAD_CAST argv[i + 1],
			                BAD_CAST argv[i + 2],
			                BAD_CAST argv[i + 3]);
		if (ret != 0)
		    printf("add command failed\n");
		i += 3;
	    } else if ((!strcmp(argv[i], "-del")) ||
		(!strcmp(argv[i], "--del"))) {
		ret = xmlCatalogRemove(BAD_CAST argv[i + 1]);
		i += 1;
	    }
	}
	
	if (noout) {
	    FILE *out;

	    out = fopen(filename, "w");
	    if (out == NULL) {
		fprintf(stderr, "could not open %s for saving\n", filename);
		noout = 0;
	    } else {
		xmlCatalogDump(out);
	    }
	}
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
