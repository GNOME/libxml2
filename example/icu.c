/*
 * icu.c: Example how to use ICU for character encoding conversion
 *
 * This example shows how to use ICU by installing a custom character
 * encoding converter with xmlCtxtSetCharEncConvImpl, available
 * since libxml2 2.14.
 *
 * This approach makes it possible to use ICU even if libxml2 is
 * compiled without ICU support. It also makes sure that *only* ICU
 * is used. Many Linux distros currently ship libxml2 with support
 * for both ICU and iconv which makes the library's behavior hard to
 * predict.
 *
 * The long-term plan is to make libxml2 only support a single
 * conversion library internally (iconv on POSIX).
 */

#include <stdio.h>
#include <libxml/parser.h>
#include <unicode/ucnv.h>

#define ICU_PIVOT_BUF_SIZE 1024

typedef struct {
    UConverter *uconv; /* for conversion between an encoding and UTF-16 */
    UConverter *utf8; /* for conversion between UTF-8 and UTF-16 */
    UChar      *pivot_source;
    UChar      *pivot_target;
    int        isInput;
    UChar      pivot_buf[ICU_PIVOT_BUF_SIZE];
} myConvCtxt;

static xmlCharEncError
icuConvert(void *vctxt, unsigned char *out, int *outlen,
           const unsigned char *in, int *inlen, int flush) {
    myConvCtxt *cd = vctxt;
    const char *ucv_in = (const char *) in;
    char *ucv_out = (char *) out;
    UConverter *target, *source;
    UErrorCode err = U_ZERO_ERROR;
    int ret;

    if ((out == NULL) || (outlen == NULL) || (inlen == NULL) || (in == NULL)) {
        if (outlen != NULL)
            *outlen = 0;
        return XML_ENC_ERR_INTERNAL;
    }

    /*
     * The ICU API can consume input, including partial sequences,
     * even if the output buffer would overflow. The remaining input
     * must be processed by calling ucnv_convertEx with a possibly
     * empty input buffer.
     */
    if (cd->isInput) {
        source = cd->uconv;
        target = cd->utf8;
    } else {
        source = cd->utf8;
        target = cd->uconv;
    }

    ucnv_convertEx(target, source, &ucv_out, ucv_out + *outlen,
                   &ucv_in, ucv_in + *inlen, cd->pivot_buf,
                   &cd->pivot_source, &cd->pivot_target,
                   cd->pivot_buf + ICU_PIVOT_BUF_SIZE,
                   /* reset */ 0, flush, &err);

    *inlen = ucv_in - (const char*) in;
    *outlen = ucv_out - (char *) out;

    if (U_SUCCESS(err)) {
        ret = XML_ENC_ERR_SUCCESS;
    } else {
        switch (err) {
            case U_TRUNCATED_CHAR_FOUND:
                /* Should only happen with flush */
                ret = XML_ENC_ERR_INPUT;
                break;

            case U_BUFFER_OVERFLOW_ERROR:
                ret = XML_ENC_ERR_SPACE;
                break;

            case U_INVALID_CHAR_FOUND:
            case U_ILLEGAL_CHAR_FOUND:
            case U_ILLEGAL_ESCAPE_SEQUENCE:
            case U_UNSUPPORTED_ESCAPE_SEQUENCE:
                ret = XML_ENC_ERR_INPUT;
                break;

            case U_MEMORY_ALLOCATION_ERROR:
                ret = XML_ENC_ERR_MEMORY;
                break;

            default:
                ret = XML_ENC_ERR_INTERNAL;
                break;
        }
    }

    return ret;
}

static xmlParserErrors
icuOpen(const char* name, int isInput, myConvCtxt **out)
{
    UErrorCode status;
    myConvCtxt *cd;

    *out = NULL;

    cd = xmlMalloc(sizeof(myConvCtxt));
    if (cd == NULL)
        return XML_ERR_NO_MEMORY;

    cd->isInput = isInput;
    cd->pivot_source = cd->pivot_buf;
    cd->pivot_target = cd->pivot_buf;

    status = U_ZERO_ERROR;
    cd->uconv = ucnv_open(name, &status);
    if (U_FAILURE(status))
        goto error;

    status = U_ZERO_ERROR;
    if (isInput) {
        ucnv_setToUCallBack(cd->uconv, UCNV_TO_U_CALLBACK_STOP,
                            NULL, NULL, NULL, &status);
    }
    else {
        ucnv_setFromUCallBack(cd->uconv, UCNV_FROM_U_CALLBACK_STOP,
                              NULL, NULL, NULL, &status);
    }
    if (U_FAILURE(status))
        goto error;

    status = U_ZERO_ERROR;
    cd->utf8 = ucnv_open("UTF-8", &status);
    if (U_FAILURE(status))
        goto error;

    *out = cd;
    return 0;

error:
    if (cd->uconv)
        ucnv_close(cd->uconv);
    xmlFree(cd);

    if (status == U_FILE_ACCESS_ERROR)
        return XML_ERR_UNSUPPORTED_ENCODING;
    if (status == U_MEMORY_ALLOCATION_ERROR)
        return XML_ERR_NO_MEMORY;
    return XML_ERR_SYSTEM;
}

static void
icuClose(myConvCtxt *cd)
{
    if (cd == NULL)
        return;
    ucnv_close(cd->uconv);
    ucnv_close(cd->utf8);
    xmlFree(cd);
}

static void
icuConvCtxtDtor(void *vctxt) {
    icuClose(vctxt);
}

static xmlParserErrors
icuConvImpl(void *vctxt, const char *name, xmlCharEncFlags flags,
            xmlCharEncodingHandler **result) {
    xmlCharEncConvFunc inFunc = NULL, outFunc = NULL;
    myConvCtxt *inputCtxt = NULL;
    myConvCtxt *outputCtxt = NULL;
    xmlParserErrors ret;

    if (flags & XML_ENC_INPUT) {
        ret = icuOpen(name, 1, &inputCtxt);
        if (ret != 0)
            goto error;
        inFunc = icuConvert;
    }

    if (flags & XML_ENC_OUTPUT) {
        ret = icuOpen(name, 0, &outputCtxt);
        if (ret != 0)
            goto error;
        outFunc = icuConvert;
    }

    return xmlCharEncNewCustomHandler(name, inFunc, outFunc, icuConvCtxtDtor,
                                      inputCtxt, outputCtxt, result);

error:
    if (inputCtxt != NULL)
        icuClose(inputCtxt);
    if (outputCtxt != NULL)
        icuClose(outputCtxt);
    return ret;
}

int
main(void) {
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    const char *xml;
    xmlChar *content;
    int ret = 0;

    /*
     * We use IBM-1051, an alias for HP Roman, as a simple example that
     * ICU supports, but iconv (typically) doesn't.
     *
     * Character code 0xDE is U+00DF Latin Small Letter Sharp S.
     */
    xml = "<doc>\xDE</doc>";

    ctxt = xmlNewParserCtxt();
    xmlCtxtSetCharEncConvImpl(ctxt, icuConvImpl, NULL);
    doc = xmlCtxtReadDoc(ctxt, BAD_CAST xml, NULL, "IBM-1051", 0);
    xmlFreeParserCtxt(ctxt);

    content = xmlNodeGetContent((xmlNodePtr) doc);

    printf("content: %s\n", content);

    if (!xmlStrEqual(content, BAD_CAST "\xC3\x9F")) {
        fprintf(stderr, "conversion failed\n");
        ret = 1;
    }

    xmlFree(content);
    xmlFreeDoc(doc);

    return ret;
}

