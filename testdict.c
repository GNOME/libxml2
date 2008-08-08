#include <string.h>
#include <libxml/parser.h>
#include <libxml/dict.h>

/* #define WITH_PRINT */

static const char *seeds[] = {
   "a", "b", "c",
   "d", "e", "f",
   "g", "h", "i",
   "j", "k", "l",

   NULL
};

#define NB_STRINGS_NS 100
#define NB_STRINGS_MAX 10000
#define NB_STRINGS_MIN 10

static xmlChar *strings[NB_STRINGS_MAX];
static const xmlChar *test1[NB_STRINGS_MAX];

static void fill_strings(void) {
    int i, j, k;

    /*
     * That's a bit nasty but the output is fine and it doesn't take hours
     * there is a small but sufficient number of duplicates, and we have
     * ":xxx" and full QNames in the last NB_STRINGS_NS values
     */
    for (i = 0; seeds[i] != NULL; i++) {
        strings[i] = xmlStrdup((const xmlChar *) seeds[i]);
	if (strings[i] == NULL) {
	    fprintf(stderr, "Out of memory while generating strings\n");
	    exit(1);
	}
    }
    for (j = 0, k = 0;i < NB_STRINGS_MAX - NB_STRINGS_NS;i++,j++) {
        strings[i] = xmlStrncatNew(strings[j], strings[k], -1);
	if (strings[i] == NULL) {
	    fprintf(stderr, "Out of memory while generating strings\n");
	    exit(1);
	}
	if (j >= 50) {
	    j = 0;
	    k++;
	}
    }
    for (j = 0; (j < 50) && (i < NB_STRINGS_MAX); i++, j+=2) {
        strings[i] = xmlStrncatNew(strings[j], (const xmlChar *) ":", -1);
	if (strings[i] == NULL) {
	    fprintf(stderr, "Out of memory while generating strings\n");
	    exit(1);
	}
    }
    for (j = NB_STRINGS_MAX - NB_STRINGS_NS, k = 0;
         i < NB_STRINGS_MAX;i++,j++) {
        strings[i] = xmlStrncatNew(strings[j], strings[k], -1);
	if (strings[i] == NULL) {
	    fprintf(stderr, "Out of memory while generating strings\n");
	    exit(1);
	}
	k += 3;
	if (k >= 50) k = 0;
    }
}

#ifdef WITH_PRINT
static void print_strings(void) {
    int i;

    for (i = 0; i < NB_STRINGS_MAX;i++) {
        printf("%s\n", strings[i]);
    }
}
#endif

static void clean_strings(void) {
    int i;

    for (i = 0; i < NB_STRINGS_MAX; i++) {
        if (strings[i] != NULL) /* really should not happen */
	    xmlFree(strings[i]);
    }
}

static int run_test1(void) {
    int i, j;
    xmlDictPtr dict;
    int ret = 0;
    xmlChar prefix[40];
    xmlChar *cur, *pref, *tmp;

    dict = xmlDictCreate();
    if (dict == NULL) {
	fprintf(stderr, "Out of memory while creating dictionary\n");
	exit(1);
    }
    memset(test1, 0, sizeof(test1));

    /*
     * Fill in NB_STRINGS_MIN, at this point the dictionary should not grow
     * and we allocate all those doing the fast key computations
     */
    for (i = 0;i < NB_STRINGS_MIN;i++) {
        test1[i] = xmlDictLookup(dict, strings[i], -1);
	if (test1[i] == NULL) {
	    fprintf(stderr, "Failed lookup for '%s'\n", strings[i]);
	    ret = 1;
	}
    }
    j = NB_STRINGS_MAX - NB_STRINGS_NS;
    /* ":foo" like strings */
    for (i = 0;i < NB_STRINGS_MIN;i++, j++) {
        test1[j] = xmlDictLookup(dict, strings[j], xmlStrlen(strings[j]));
	if (test1[j] == NULL) {
	    fprintf(stderr, "Failed lookup for '%s'\n", strings[j]);
	    ret = 1;
	}
    }
    /* "a:foo" like strings */
    j = NB_STRINGS_MAX - NB_STRINGS_MIN;
    for (i = 0;i < NB_STRINGS_MIN;i++, j++) {
        test1[j] = xmlDictLookup(dict, strings[j], xmlStrlen(strings[j]));
	if (test1[j] == NULL) {
	    fprintf(stderr, "Failed lookup for '%s'\n", strings[j]);
	    ret = 1;
	}
    }

    /*
     * At this point allocate all the strings
     * the dictionary will grow in the process, reallocate more string tables
     * and switch to the better key generator
     */
    for (i = 0;i < NB_STRINGS_MAX;i++) {
        if (test1[i] != NULL)
	    continue;
	test1[i] = xmlDictLookup(dict, strings[i], -1);
	if (test1[i] == NULL) {
	    fprintf(stderr, "Failed lookup for '%s'\n", strings[i]);
	    ret = 1;
	}
    }

    /*
     * Now we can start to test things, first that all strings belongs to
     * the dict
     */
    for (i = 0;i < NB_STRINGS_MAX;i++) {
        if (!xmlDictOwns(dict, test1[i])) {
	    fprintf(stderr, "Failed ownership failure for '%s'\n",
	            strings[i]);
	    ret = 1;
	}
    }

    /*
     * Then that another lookup to the string will return the same
     */
    for (i = 0;i < NB_STRINGS_MAX;i++) {
        if (xmlDictLookup(dict, strings[i], -1) != test1[i]) {
	    fprintf(stderr, "Failed re-lookup check for %d, '%s'\n",
	            i, strings[i]);
	    ret = 1;
	}
    }

    /*
     * More complex, check the QName lookups
     */
    for (i = NB_STRINGS_MAX - NB_STRINGS_NS;i < NB_STRINGS_MAX;i++) {
        cur = strings[i];
	pref = &prefix[0];
	while (*cur != ':') *pref++ = *cur++;
	cur++;
	*pref = 0;
	tmp = xmlDictQLookup(dict, &prefix[0], cur);
	if (xmlDictQLookup(dict, &prefix[0], cur) != test1[i]) {
	    fprintf(stderr, "Failed lookup check for '%s':'%s'\n",
	            &prefix[0], cur);
            ret = 1;
	}
    }

    xmlDictFree(dict);
    return(0);
}

int main(void)
{
    int ret;

    LIBXML_TEST_VERSION
    fill_strings();
#ifdef WITH_PRINT
    print_strings();
#endif
    ret = run_test1();
    clean_strings();
    xmlCleanupParser();
    xmlMemoryDump();
    return(ret);
}
