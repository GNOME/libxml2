/**
 * @file
 * 
 * @brief lists interfaces
 * 
 * this module implement the list support used in
 * various place in the library.
 *
 * @copyright See Copyright for the status of this software.
 *
 * @author Gary Pennington
 */

#ifndef __XML_LINK_INCLUDE__
#define __XML_LINK_INCLUDE__

#include <libxml/xmlversion.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _xmlLink xmlLink;
typedef xmlLink *xmlLinkPtr;

typedef struct _xmlList xmlList;
typedef xmlList *xmlListPtr;

/**
 * Callback function used to free data from a list.
 *
 * @param lk  the data to deallocate
 */
typedef void (*xmlListDeallocator) (xmlLinkPtr lk);
/**
 * Callback function used to compare 2 data.
 *
 * @param data0  the first data
 * @param data1  the second data
 * @returns 0 is equality, -1 or 1 otherwise depending on the ordering.
 */
typedef int  (*xmlListDataCompare) (const void *data0, const void *data1);
/**
 * Callback function used when walking a list with xmlListWalk().
 *
 * @param data  the data found in the list
 * @param user  extra user provided data to the walker
 * @returns 0 to stop walking the list, 1 otherwise.
 */
typedef int (*xmlListWalker) (const void *data, void *user);

/* Creation/Deletion */
XMLPUBFUN xmlListPtr
		xmlListCreate		(xmlListDeallocator deallocator,
	                                 xmlListDataCompare compare);
XMLPUBFUN void
		xmlListDelete		(xmlListPtr l);

/* Basic Operators */
XMLPUBFUN void *
		xmlListSearch		(xmlListPtr l,
					 void *data);
XMLPUBFUN void *
		xmlListReverseSearch	(xmlListPtr l,
					 void *data);
XMLPUBFUN int
		xmlListInsert		(xmlListPtr l,
					 void *data) ;
XMLPUBFUN int
		xmlListAppend		(xmlListPtr l,
					 void *data) ;
XMLPUBFUN int
		xmlListRemoveFirst	(xmlListPtr l,
					 void *data);
XMLPUBFUN int
		xmlListRemoveLast	(xmlListPtr l,
					 void *data);
XMLPUBFUN int
		xmlListRemoveAll	(xmlListPtr l,
					 void *data);
XMLPUBFUN void
		xmlListClear		(xmlListPtr l);
XMLPUBFUN int
		xmlListEmpty		(xmlListPtr l);
XMLPUBFUN xmlLinkPtr
		xmlListFront		(xmlListPtr l);
XMLPUBFUN xmlLinkPtr
		xmlListEnd		(xmlListPtr l);
XMLPUBFUN int
		xmlListSize		(xmlListPtr l);

XMLPUBFUN void
		xmlListPopFront		(xmlListPtr l);
XMLPUBFUN void
		xmlListPopBack		(xmlListPtr l);
XMLPUBFUN int
		xmlListPushFront	(xmlListPtr l,
					 void *data);
XMLPUBFUN int
		xmlListPushBack		(xmlListPtr l,
					 void *data);

/* Advanced Operators */
XMLPUBFUN void
		xmlListReverse		(xmlListPtr l);
XMLPUBFUN void
		xmlListSort		(xmlListPtr l);
XMLPUBFUN void
		xmlListWalk		(xmlListPtr l,
					 xmlListWalker walker,
					 void *user);
XMLPUBFUN void
		xmlListReverseWalk	(xmlListPtr l,
					 xmlListWalker walker,
					 void *user);
XMLPUBFUN void
		xmlListMerge		(xmlListPtr l1,
					 xmlListPtr l2);
XMLPUBFUN xmlListPtr
		xmlListDup		(xmlListPtr old);
XMLPUBFUN int
		xmlListCopy		(xmlListPtr cur,
					 xmlListPtr old);
/* Link operators */
XMLPUBFUN void *
		xmlLinkGetData          (xmlLinkPtr lk);

/* xmlListUnique() */
/* xmlListSwap */

#ifdef __cplusplus
}
#endif

#endif /* __XML_LINK_INCLUDE__ */
