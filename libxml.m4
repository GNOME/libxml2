dnl Code shamelessly stolen from glib-config by Sebastian Rittau
dnl AM_PATH_XML([MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
AC_DEFUN(AM_PATH_XML,[
AC_ARG_WITH(xml-prefix,
            [  --with-xml-prefix=PFX    Prefix where libxml is installed (optional)],
            xml_config_prefix="$withval", xml_config_prefix="")
AC_ARG_ENABLE(xmltest,
              [  --disable-xmltest        Do not try to compile and run a test XML program],,
              enable_xmltest=yes)

  if test x$xml_config_prefix != x ; then
    xml_config_args="$xml_config_args --prefix=$xml_config_prefix"
    if test x${XML_CONFIG+set} != xset ; then
      XML_CONFIG=$xml_config_prefix/bin/xml-config
    fi
  fi

  AC_PATH_PROG(XML_CONFIG, xml-config, no)
  min_xml_version=ifelse([$1], ,2.0.0, [$1])
  AC_MSG_CHECKING(for libxml - version >= $min_xml_version)
  no_xml=""
  if test "$XML_CONFIG" = "no" ; then
    no_xml=yes
  else
    XML_CFLAGS=`$XML_CONFIG $xml_config_args --cflags`
    XML_LIBS=`$XML_CONFIG $xml_config_args --libs`
    xml_config_major_version=`$XML_CONFIG $xml_config_args --version | \
      sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    xml_config_minor_version=`$XML_CONFIG $xml_config_args --version | \
      sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    xml_config_micro_version=`$XML_CONFIG $xml_config_args --version | \
      sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_xmltest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $XML_CFLAGS"
      LIBS="$XML_LIBS $LIBS"
dnl
dnl Now check if the installed libxml is sufficiently new.
dnl
      rm -f conf.xmltest
      AC_TRY_RUN([
#include <stdlib.h>
#include <stdio.h>
#include <xmlversion.h>
#include <parser.h>

int
main()
{
  int xml_major_version, xml_minor_version, xml_micro_version;
  int major, minor, micro;
  char *tmp_version;

  system("touch conf.xmltest");

  tmp_version = xmlStrdup("$min_xml_version");
  if(sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
    printf("%s, bad version string\n", "$min_xml_version");
    exit(1);
  }

  tmp_version = xmlStrdup(LIBXML_DOTTED_VERSION);
  if(sscanf(tmp_version, "%d.%d.%d", &xml_major_version, &xml_minor_version, &xml_micro_version) != 3) {
    printf("%s, bad version string\n", "$min_xml_version");
    exit(1);
  }

  if((xml_major_version != $xml_config_major_version) ||
     (xml_minor_version != $xml_config_minor_version) ||
     (xml_micro_version != $xml_config_micro_version))
    {
      printf("\n*** 'xml-config --version' returned %d.%d.%d, but libxml (%d.%d.%d)\n", 
             $xml_config_major_version, $xml_config_minor_version, $xml_config_micro_version,
             xml_major_version, xml_minor_version, xml_micro_version);
      printf("*** was found! If xml-config was correct, then it is best\n");
      printf("*** to remove the old version of libxml. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If xml-config was wrong, set the environment variable XML_CONFIG\n");
      printf("*** to point to the correct copy of xml-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
  else
    {
      if ((xml_major_version > major) ||
          ((xml_major_version == major) && (xml_minor_version > minor)) ||
          ((xml_major_version == major) && (xml_minor_version == minor) &&
           (xml_micro_version >= micro)))
        {
          return 0;
        }
      else
        {
          printf("\n*** An old version of libxml (%d.%d.%d) was found.\n",
            xml_major_version, xml_minor_version, xml_micro_version);
          printf("*** You need a version of libxml newer than %d.%d.%d. The latest version of\n",
            major, minor, micro);
          printf("*** libxml is always available from ftp://ftp.gnome.org.\n");
          printf("***\n");
          printf("*** If you have already installed a sufficiently new version, this error\n");
          printf("*** probably means that the wrong copy of the xml-config shell script is\n");
          printf("*** being found. The easiest way to fix this is to remove the old version\n");
          printf("*** of libxml, but you can also set the XML_CONFIG environment to point to the\n");
          printf("*** correct copy of xml-config. (In this case, you will have to\n");
          printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
          printf("*** so that the correct libraries are found at run-time))\n");
        }
    }
  return 1;
}
],, no_xml=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])

      CFLAGS="$ac_save_CFLAGS"
      LIBS="$ac_save_LIBS"
    fi
  fi

  if test "x$no_xml" = x ; then
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    AC_MSG_RESULT(no)
    if test "$XML_CONFIG" = "no" ; then
      echo "*** The xml-config script installed by libxml could not be found"
      echo "*** If libxml was installed in PREFIX, make sure PREFIX/bin is in"
      echo "*** your path, or set the XML_CONFIG environment variable to the"
      echo "*** full path to xml-config."
    else
      if test -f conf.xmltest ; then
        :
      else
        echo "*** Could not run libxml test program, checking why..."
        CFLAGS="$CFLAGS $XML_CFLAGS"
        LIBS="$LIBS $XML_LIBS"
        dnl FIXME: AC_TRY_LINK
      fi
    fi

    XML_CFLAGS=""
    XML_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(XML_CFLAGS)
  AC_SUBST(XML_LIBS)
  rm -f conf.xmltest
])

# Configure paths for LIBXML2
# Toshio Kuratomi 2001-04-21
# Adapted from:
# Configure paths for GLIB
# Owen Taylor     97-11-3

dnl AM_PATH_XML2([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND [, MODULES]]]])
dnl Test for LIBXML, and define LIBXML_CFLAGS and LIBXML_LIBS
dnl
AC_DEFUN(AM_PATH_XML2,
[dnl 
dnl Get the cflags and libraries from the xml2-config script
dnl
AC_ARG_WITH(libxml-prefix,[  --with-libxml-prefix=PFX   Prefix where LIBXML is installed (optional)],
            libxml_config_prefix="$withval", libxml_config_prefix="")
AC_ARG_WITH(libxml-exec-prefix,[  --with-libxml-exec-prefix=PFX Exec prefix where LIBXML is installed (optional)],
            libxml_config_exec_prefix="$withval", libxml_config_exec_prefix="")
AC_ARG_ENABLE(libxmltest, [  --disable-libxmltest       Do not try to compile and run a test LIBXML program],
		    , enable_libxmltest=yes)

  if test x$libxml_config_exec_prefix != x ; then
     libxml_config_args="$libxml_config_args --exec-prefix=$libxml_config_exec_prefix"
     if test x${LIBXML_CONFIG2+set} != xset ; then
        LIBXML_CONFIG2=$libxml_config_exec_prefix/bin/xml2-config
     fi
  fi
  if test x$libxml_config_prefix != x ; then
     libxml_config_args="$libxml_config_args --prefix=$libxml_config_prefix"
     if test x${LIBXML_CONFIG2+set} != xset ; then
        LIBXML_CONFIG2=$libxml_config_prefix/bin/xml2-config
     fi
  fi

  AC_PATH_PROG(LIBXML_CONFIG2, xml2-config, no)
  min_libxml_version=ifelse([$1], ,2.0.0,$1)
  AC_MSG_CHECKING(for LIBXML - version >= $min_libxml_version)
  no_libxml=""
  if test "$LIBXML_CONFIG2" = "no" ; then
    no_libxml=yes
  else
    LIBXML_CFLAGS=`$LIBXML_CONFIG2 $libxml_config_args --cflags`
    LIBXML_LIBS=`$LIBXML_CONFIG2 $libxml_config_args --libs`
    libxml_config_major_version=`$LIBXML_CONFIG2 $libxml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    libxml_config_minor_version=`$LIBXML_CONFIG2 $libxml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    libxml_config_micro_version=`$LIBXML_CONFIG2 $libxml_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`

    if test "x$enable_libxmltest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBXML_CFLAGS"
      LIBS="$LIBXML_LIBS $LIBS"
dnl
dnl Now check if the installed LIBXML is sufficiently new. (Also sanity
dnl checks the results of xml2-config to some extent
dnl
      rm -f conf.libxmltest
      AC_TRY_RUN([
#include <xmlversion.h>
#include <stdio.h>
#include <stdlib.h>

int 
main ()
{
  int major, minor, micro;
  int libxml_major_version, libxml_minor_version, libxml_micro_version;
  char *tmp_version;

  system ("touch conf.libxmltest");

  /* Capture xml2-config output via autoconf/configure variables */
  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = (char *)strdup("$min_libxml_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_libxml_version");
     exit(1);
   }
   free(tmp_version);

   /* Capture the version information from the header files */
   sscanf(LIBXML_DOTTED_VERSION, "%d.%d.%d", &libxml_major_version, &libxml_minor_version, &libxml_micro_version);

 /* Compare xml2-config output to the libxml headers */
  if ((libxml_major_version != $libxml_config_major_version) ||
      (libxml_minor_version != $libxml_config_minor_version) ||
      (libxml_micro_version != $libxml_config_micro_version))
    {
      printf("*** LIBXML header files (version %d.%d.%d) do not match\n",
	     libxml_major_version, libxml_minor_version, libxml_micro_version);
      printf("*** xml2-config (version %d.%d.%d)\n",
	     $libxml_config_major_version, $libxml_config_minor_version, $libxml_config_micro_version);
      return 1;
    } 
/* Compare the headers to the library to make sure we match */
  /* Less than ideal -- doesn't provide us with return value feedback, 
   * only exits if there's a serious mismatch between header and library.
   */
  	LIBXML_TEST_VERSION;
    if ((libxml_major_version > major) ||
        ((libxml_major_version == major) && (libxml_minor_version > minor)) ||
        ((libxml_major_version == major) && (libxml_minor_version == minor) && (libxml_micro_version >= micro)))
      {
        return 0;
       }
     else
      {
        printf("\n*** An old version of LIBXML (%d.%d.%d) was found.\n",
               libxml_major_version, libxml_minor_version, libxml_micro_version);
        printf("*** You need a version of LIBXML newer than %d.%d.%d. The latest version of\n",
	       major, minor, micro);
        printf("*** LIBXML is always available from ftp://ftp.xmlsoft.org.\n");
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the xml2-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBXML, but you can also set the LIBXML_CONFIG2 environment to point to the\n");
        printf("*** correct copy of xml2-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
    }
  return 1;
}
],, no_libxml=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_libxml" = x ; then
     AC_MSG_RESULT(yes (version $libxml_config_major_version.$libxml_config_minor_version.$libxml_config_micro_version))
     ifelse([$2], , :, [$2])     
  else
     AC_MSG_RESULT(no)
     if test "$LIBXML_CONFIG2" = "no" ; then
       echo "*** The xml2-config script installed by LIBXML could not be found"
       echo "*** If LIBXML was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBXML_CONFIG2 environment variable to the"
       echo "*** full path to xml2-config."
     else
       if test -f conf.libxmltest ; then
        :
       else
          echo "*** Could not run LIBXML test program, checking why..."
          CFLAGS="$CFLAGS $LIBXML_CFLAGS"
          LIBS="$LIBS $LIBXML_LIBS"
          AC_TRY_LINK([
#include <xmlversion.h>
#include <stdio.h>
],      [ LIBXML_TEST_VERSION; return 0;],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBXML or finding the wrong"
          echo "*** version of LIBXML. If it is not finding LIBXML, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
	  echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBXML was incorrectly installed"
          echo "*** or that you have moved LIBXML since it was installed. In the latter case, you"
          echo "*** may want to edit the xml2-config script: $LIBXML_CONFIG2" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBXML_CFLAGS=""
     LIBXML_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBXML_CFLAGS)
  AC_SUBST(LIBXML_LIBS)
  rm -f conf.libxmltest
])
