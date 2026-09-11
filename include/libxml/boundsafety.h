/*
 * boundsafety.h: portable wrappers for Clang -fbounds-safety annotations
 *
 * First-CL infrastructure for secure-by-design memory safety (Google Patch
 * Rewards Tier-1 / core parsers). Macros are inert unless the build enables
 * LIBXML_BOUNDS_SAFETY and the compiler supports bounds_safety.
 *
 * See NOTES.md for adoption plan. Do not enable by default.
 *
 * Author: Jeff <jeff@incrediblybased.co>
 */

#ifndef __XML_BOUNDS_SAFETY_H__
#define __XML_BOUNDS_SAFETY_H__

/*
 * When LIBXML_BOUNDS_SAFETY is not defined (default / option OFF), every
 * annotation expands to empty so ordinary toolchains are unaffected.
 */
#if defined(LIBXML_BOUNDS_SAFETY) && defined(__has_feature)
# if __has_feature(bounds_safety)
#  define XML_SIZED_BY(N)           __sized_by(N)
#  define XML_SIZED_BY_OR_NULL(N)   __sized_by_or_null(N)
#  define XML_COUNTED_BY(N)         __counted_by(N)
#  define XML_COUNTED_BY_OR_NULL(N) __counted_by_or_null(N)
#  define XML_ENDED_BY(P)           __ended_by(P)
#  define XML_ENDED_BY_OR_NULL(P)   __ended_by_or_null(P)
# endif
#endif

#ifndef XML_SIZED_BY
# define XML_SIZED_BY(N)
# define XML_SIZED_BY_OR_NULL(N)
# define XML_COUNTED_BY(N)
# define XML_COUNTED_BY_OR_NULL(N)
# define XML_ENDED_BY(P)
# define XML_ENDED_BY_OR_NULL(P)
#endif

#endif /* __XML_BOUNDS_SAFETY_H__ */
