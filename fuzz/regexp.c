/*
 * regexp.c: a libFuzzer target to test the regexp module.
 *
 * See Copyright for the status of this software.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libxml/xmlregexp.h>
#include "fuzz.h"

int
LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                     char ***argv ATTRIBUTE_UNUSED) {
    xmlFuzzMemSetup();

    return 0;
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
    xmlRegexpPtr regexp;
    size_t failurePos;
    const char *str1;

    if (size > 200)
        return(0);

    xmlFuzzDataInit(data, size);
    failurePos = xmlFuzzReadInt(4) % (size * 8 + 100);
    str1 = xmlFuzzReadString(NULL);

    xmlFuzzInjectFailure(failurePos);
    regexp = xmlRegexpCompile(BAD_CAST str1);
    if (xmlFuzzMallocFailed() && regexp != NULL) {
        fprintf(stderr, "malloc failure not reported\n");
        abort();
    }
    /* xmlRegexpExec has pathological performance in too many cases. */
#if 0
    xmlRegexpExec(regexp, BAD_CAST str2);
#endif
    xmlRegFreeRegexp(regexp);

    xmlFuzzInjectFailure(0);
    xmlFuzzDataCleanup();
    xmlResetLastError();

    return 0;
}

