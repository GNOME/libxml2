/*
 * fuzz.h: Common functions and macros for fuzzing.
 *
 * See Copyright for the status of this software.
 */

#ifndef __XML_FUZZERCOMMON_H__
#define __XML_FUZZERCOMMON_H__

#include <stddef.h>
#include <libxml/parser.h>

#ifdef __cplusplus
extern "C" {
#endif

int
LLVMFuzzerInitialize(int *argc, char ***argv);

int
LLVMFuzzerTestOneInput(const char *data, size_t size);

void
xmlFuzzErrorFunc(void *ctx ATTRIBUTE_UNUSED, const char *msg ATTRIBUTE_UNUSED,
                 ...);

void
xmlFuzzDataInit(const char *data, size_t size);

void
xmlFuzzDataCleanup(void);

int
xmlFuzzReadInt(void);

const char *
xmlFuzzReadRemaining(size_t *size);

xmlParserInputPtr
xmlFuzzEntityRecorder(const char *URL, const char *ID, xmlParserCtxtPtr ctxt);

void
xmlFuzzReadEntities(void);

const char *
xmlFuzzMainUrl(void);

const char *
xmlFuzzMainEntity(size_t *size);

xmlParserInputPtr
xmlFuzzEntityLoader(const char *URL, const char *ID, xmlParserCtxtPtr ctxt);

size_t
xmlFuzzExtractStrings(const char *data, size_t size, char **strings,
                      size_t numStrings);

#ifdef __cplusplus
}
#endif

#endif /* __XML_FUZZERCOMMON_H__ */

