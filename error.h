#ifndef error_h_
#define error_h_

#include "parser.h"

void xmlParserError(xmlParserCtxtPtr ctxt, const char *msg, ...);
void xmlParserWarning(xmlParserCtxtPtr ctxt, const char *msg, ...);
#endif
