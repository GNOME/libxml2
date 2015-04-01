      * Summary: Unicode character range checking
      * Description: this module exports interfaces for the character
      *               range validation APIs
      *
      * Copy: See Copyright for the status of this software.
      *
      * Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.

      /if not defined(XML_CHVALID_H__)
      /define XML_CHVALID_H__

      /include "libxmlrpg/xmlversion"
      /include "libxmlrpg/xmlTypesC"
      /include "libxmlrpg/xmlstring"

      * Define our typedefs and structures

     d xmlChSRangePtr  s               *   based(######typedef######)

     d xmlChSRange     ds                  based(xmlChSRangePtr)
     d                                     align qualified
     d  low                                like(xmlCushort)
     d  high                               like(xmlCushort)

     d xmlChLRangePtr  s               *   based(######typedef######)

     d xmlChLRange     ds                  based(xmlChLRangePtr)
     d                                     align qualified
     d  low                                like(xmlCuint)
     d  high                               like(xmlCuint)

     d xmlChRangeGroupPtr...
     d                 s               *   based(######typedef######)

     d xmlChRangeGroup...
     d                 ds                  based(xmlChRangeGroupPtr)
     d                                     align qualified
     d  nbShortRange                 10i 0
     d  nbLongRange                  10i 0
     d  shortRange                         like(xmlChSRangePtr)
     d  longRange                          like(xmlChLRangePtr)

      * Range checking routine

     d xmlCharInRange  pr            10i 0 extproc('xmlCharInRange')
     d val                                 value like(xmlCuint)
     d group                               like(xmlChRangeGroupPtr)             const

     d xmlIsBaseCharGroup...
     d                 ds                  import('xmlIsBaseCharGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsCharGroup...
     d                 ds                  import('xmlIsCharGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsCombiningGroup...
     d                 ds                  import('xmlIsCombiningGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsDigitGroup...
     d                 ds                  import('xmlIsDigitGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsExtenderGroup...
     d                 ds                  import('xmlIsExtenderGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsIdeographicGroup...
     d                 ds                  import('xmlIsIdeographicGroup')
     d                                     likeds(xmlChRangeGroup)              const

     d xmlIsBaseChar   pr            10i 0 extproc('xmlIsBaseChar')
     d ch                                  value like(xmlCuint)

     d xmlIsBlank      pr            10i 0 extproc('xmlIsBlank')
     d ch                                  value like(xmlCuint)

     d xmlIsChar       pr            10i 0 extproc('xmlIsChar')
     d ch                                  value like(xmlCuint)

     d xmlIsCombining  pr            10i 0 extproc('xmlIsCombining')
     d ch                                  value like(xmlCuint)

     d xmlIsDigit      pr            10i 0 extproc('xmlIsDigit')
     d ch                                  value like(xmlCuint)

     d xmlIsExtender   pr            10i 0 extproc('xmlIsExtender')
     d ch                                  value like(xmlCuint)

     d xmlIsIdeographic...
     d                 pr            10i 0 extproc('xmlIsIdeographic')
     d ch                                  value like(xmlCuint)

     d xmlIsPubidChar  pr            10i 0 extproc('xmlIsPubidChar')
     d ch                                  value like(xmlCuint)

      /endif                                                                    XML_CHVALID_H__
