/*
 * chvalid.c:	this module implements the character range
 *		validation APIs
 */

#define IN_LIBXML
#include "libxml.h"
#include <libxml/chvalid.h>

#include <stddef.h>

/*
 * The initial tables ({func_name}_tab) are used to validate whether a
 * single-byte character is within the specified group.  Each table
 * contains 256 bytes, with each byte representing one of the 256
 * possible characters.  If the table byte is set, the character is
 * allowed.
 *
 */

#include "codegen/ranges.inc"

/**
 * Does a binary search of the range table to determine if char
 * is valid
 *
 * @param val  character to be validated
 * @param rptr  pointer to range to be used to validate
 * @returns true if character valid, false otherwise
 */
int
xmlCharInRange (unsigned int val, const xmlChRangeGroup *rptr) {
    int low, high, mid;
    const xmlChSRange *sptr;
    const xmlChLRange *lptr;

    if (rptr == NULL) return(0);
    if (val < 0x10000) {	/* is val in 'short' or 'long'  array? */
	if (rptr->nbShortRange == 0)
	    return 0;
	low = 0;
	high = rptr->nbShortRange - 1;
	sptr = rptr->shortRange;
	while (low <= high) {
	    mid = (low + high) / 2;
	    if ((unsigned short) val < sptr[mid].low) {
		high = mid - 1;
	    } else {
		if ((unsigned short) val > sptr[mid].high) {
		    low = mid + 1;
		} else {
		    return 1;
		}
	    }
	}
    } else {
	if (rptr->nbLongRange == 0) {
	    return 0;
	}
	low = 0;
	high = rptr->nbLongRange - 1;
	lptr = rptr->longRange;
	while (low <= high) {
	    mid = (low + high) / 2;
	    if (val < lptr[mid].low) {
		high = mid - 1;
	    } else {
		if (val > lptr[mid].high) {
		    low = mid + 1;
		} else {
		    return 1;
		}
	    }
	}
    }
    return 0;
}


/**
 * This function is DEPRECATED.
 * Use xmlIsBaseChar_ch() or xmlIsBaseCharQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsBaseChar(unsigned int ch) {
    return(xmlIsBaseCharQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsBlank_ch() or xmlIsBlankQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsBlank(unsigned int ch) {
    return(xmlIsBlankQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsChar_ch() or xmlIsCharQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsChar(unsigned int ch) {
    return(xmlIsCharQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsCombiningQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsCombining(unsigned int ch) {
    return(xmlIsCombiningQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsDigit_ch() or xmlIsDigitQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsDigit(unsigned int ch) {
    return(xmlIsDigitQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsExtender_ch() or xmlIsExtenderQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsExtender(unsigned int ch) {
    return(xmlIsExtenderQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsIdeographicQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsIdeographic(unsigned int ch) {
    return(xmlIsIdeographicQ(ch));
}


/**
 * This function is DEPRECATED.
 * Use xmlIsPubidChar_ch() or xmlIsPubidCharQ() instead
 *
 * @param ch  character to validate
 * @returns true if argument valid, false otherwise
 */
int
xmlIsPubidChar(unsigned int ch) {
    return(xmlIsPubidCharQ(ch));
}

