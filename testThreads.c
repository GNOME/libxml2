#include <stdlib.h>
#include <features.h>
#include <libxml/xmlversion.h>

#ifdef LIBXML_THREAD_ENABLED
#include <libxml/globals.h>
#include <libxml/threads.h>
#include <libxml/parser.h>
#include <libxml/catalog.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define	MAX_ARGC	20
static pthread_t tid[MAX_ARGC];

static const char *catalog = "test/threads/complex.xml";
static const char *testfiles[] = {
    "test/threads/abc.xml",
    "test/threads/acb.xml",
    "test/threads/bac.xml",
    "test/threads/bca.xml",
    "test/threads/cab.xml",
    "test/threads/cba.xml",
    "test/threads/invalid.xml",
};

static void *
thread_specific_data(void *private_data)
{
    xmlDocPtr myDoc;
    const char *filename = (const char *) private_data;

    if (!strcmp(filename, "test/thread/invalid.xml") == 0) {
        xmlDoValidityCheckingDefaultValue = 0;
        xmlGenericErrorContext = stdout;
    } else {
        xmlDoValidityCheckingDefaultValue = 1;
        xmlGenericErrorContext = stderr;
    }
    myDoc = xmlParseFile(filename);
    if (myDoc) {
        xmlFreeDoc(myDoc);
    } else
        printf("parse failed\n");
    if (!strcmp(filename, "test/thread/invalid.xml") == 0) {
        if (xmlDoValidityCheckingDefaultValue != 0)
	    printf("ValidityCheckingDefaultValue override failed\n");
        if (xmlGenericErrorContext != stdout)
	    printf("ValidityCheckingDefaultValue override failed\n");
    } else {
        if (xmlDoValidityCheckingDefaultValue != 1)
	    printf("ValidityCheckingDefaultValue override failed\n");
        if (xmlGenericErrorContext != stderr)
	    printf("ValidityCheckingDefaultValue override failed\n");
    }
    return (NULL);
}

int
main()
{
    unsigned int i;
    unsigned int num_threads = sizeof(testfiles) / sizeof(testfiles[0]);

    xmlInitParser();
    xmlLoadCatalog(catalog);

    for (i = 0; i < num_threads; i++)
        pthread_create(&tid[i], 0, thread_specific_data, (void *) testfiles[i]);
    for (i = 0; i < num_threads; i++)
        pthread_join(tid[i], NULL);

    xmlCleanupParser();
    xmlMemoryDump();
    return (0);
}

#else /* !LIBXML_THREADS_ENABLED */
int
main()
{
    fprintf(stderr, "libxml was not compiled with thread support\n");
    return (0);
}
#endif
