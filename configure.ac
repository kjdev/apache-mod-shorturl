#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(mod_shorturl, 0.0.1,[])

AC_CONFIG_SRCDIR([mod_shorturl.cpp])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(mod_shorturl, 0.0.1, [NO-DEFINE])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Checks for programs.
AC_PROG_CXX
AC_PROG_LIBTOOL

# Option for shorturl debug log level
AC_ARG_WITH(shorturl-debug-log,
  AC_HELP_STRING([--with-shorturl-debug-log=LEVEL],
    [shorturl debug log level [default=no]]),
  [SHORTURL_DEBUG_LOG="${withval}"],
  [SHORTURL_DEBUG_LOG=no]
)
AS_IF([test "x${SHORTURL_DEBUG_LOG}" != xno],
    [AC_DEFINE_UNQUOTED([AP_SHORTURL_DEBUG_LOG_LEVEL],
      [${SHORTURL_DEBUG_LOG}], [shorturl debug log level])]
)

# Checks for boost.
# TODO

# Checks for mongoclient.
AC_ARG_WITH(
  mongo,
  [AC_HELP_STRING([--with-mongo=PATH],
    [mongoDB include path [default=/usr/include]])],
  [MONGO_PATH="$withval"],
  [MONGO_PATH="/usr/include"]
)

AC_CHECK_FILE(
  "${MONGO_PATH}/mongo/client/dbclient.h",
  [MONGO_INCLUDEDIR=${MONGO_PATH}],
  [AC_MSG_ERROR([Missing required mongoDB client header.])]
)

AC_ARG_WITH(
  mongo-lib,
  [AC_HELP_STRING([--with-mongo-lib=PATH],
    [mongo client library path [default=no]])],
  [MONGO_LIBPATH="$withval"],
  [MONGO_LIBPATH="no"]
)

AS_IF([test "x${MONGO_LIBPATH}" != "xno"],
  MONGO_LDFLAGS="-L${MONGO_LIBPATH}"
)

AC_MSG_CHECKING([for mongoDB client library])
AC_LANG(C++)
SAVED_LDFLAGS=$LDFLAGS
LDFLAGS="$LDFLAGS ${MONGO_LDFLAGS} -lmongoclient -lboost_system-mt"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [#include "mongo/client/dbclient.h"],
    [mongo::DBClientConnection dummy])],
  [MONGO_LIBS="-lmongoclient"],
  [AC_MSG_ERROR([Missing required mongoDB client library.])]
)
AC_MSG_RESULT(yes)
LDFLAGS=$SAVED_LDFLAGS

# mongoDB client libraries.
MONGO_INCLUDES="-I${MONGO_INCLUDEDIR}"
MONGO_LDFLAGS="${MONGO_LDFLAGS} ${MONGO_LIBS}"
AC_SUBST(MONGO_INCLUDES)
AC_SUBST(MONGO_LDFLAGS)
AC_SUBST(MONGO_LIBS)


# Checks for apxs.
AC_ARG_WITH(apxs,
  [AC_HELP_STRING([--with-apxs=PATH], [apxs path [default=yes]])],
  [APXS_PATH="$withval"],
  [APXS_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"]
)

AC_PATH_PROG(APXS, apxs, no, ${APXS_PATH})

AS_IF([test "x${APXS}" = "xno"], AC_MSG_ERROR([apxs not found]),
  [test "x${APXS}" = "x"], AC_MSG_ERROR([apxs not found])
)

APXS_CFLAGS=`${APXS} -q CFLAGS 2> /dev/null`
APXS_CPPFLAGS=`${APXS} -q CPPFLAGS 2> /dev/null`
APXS_LDFLAGS=`${APXS} -q LDFLAGS 2> /dev/null`
APXS_LIBS=`${APXS} -q LIBS 2> /dev/null`
APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR 2> /dev/null`

APXS_INCLUDEDIR=`${APXS} -q INCLUDEDIR 2> /dev/null`
APXS_INCLUDES="-I${APXS_INCLUDEDIR}"

# Checks for apr.
AC_ARG_WITH(apr,
  [AC_HELP_STRING([--with-apr=PATH], [apr config path [default=yes]])],
  [APR_CONFIG="$withval"],
  [with_apr=yes]
)

AC_MSG_CHECKING([for apr])
AS_IF([test "x$with_apr" != "xno"],
  [
   if test ! -x "${APR_CONFIG}" -o -z "${APR_CONFIG}"; then
     APR_PATH=`${APXS} -q APR_BINDIR 2> /dev/null`
     APR_CONFIG="${APR_PATH}/apr-1-config"
     if test ! -x "${APR_CONFIG}"; then
       APR_CONFIG="${APR_PATH}/apr-config"
     fi
   fi
   APR_INCLUDES=`${APR_CONFIG} --includes 2> /dev/null`
   APR_CFLAGS=`${APR_CONFIG} --cflags 2> /dev/null`
   APR_CPPFLAGS=`${APR_CONFIG} --cppflags 2> /dev/null`
   APR_LDFLAGS=`${APR_CONFIG} --ldflags 2> /dev/null`
   APR_LIBS=`${APR_CONFIG} --libs 2> /dev/null`
   AC_MSG_RESULT(found)
  ],
  AC_MSG_ERROR(apr not found)
)

# Checks for apu.
AC_ARG_WITH(apu,
  [AC_HELP_STRING([--with-apu=PATH], [apu config path [default=no]])],
  [APU_CONFIG="$withval"],
  [with_apu=no]
)

AC_MSG_CHECKING([whether apu])
AS_IF([test "x$with_apu" != "xno"],
  [
   if test ! -x "${APU_CONFIG}" -o -z "${APU_CONFIG}"; then
     APU_PATH=`${APXS} -q APU_BINDIR 2> /dev/null`
     APU_CONFIG="${APU_PATH}/apu-1-config"
     if test ! -x "${APU_CONFIG}"; then
       APU_CONFIG="${APU_PATH}/apu-config"
     fi
   fi
   APU_INCLUDES=`${APU_CONFIG} --includes 2>/dev/null`
   APU_CFLAGS=`${APU_CONFIG} --cflags 2> /dev/null`
   APU_CPPFLAGS=`${APU_CONFIG} --cppflags 2> /dev/null`
   APU_LDFLAGS=`${APU_CONFIG} --ldflags 2> /dev/null`
   APU_LIBS=`${APU_CONFIG} --libs 2> /dev/null`
   AC_MSG_RESULT(enable)
  ],
  AC_MSG_RESULT(disable)
)

# Checks for apreq2.
AC_ARG_WITH(apreq2,
  [AC_HELP_STRING([--with-apreq2=PATH], [apreq2 config path [default=no]])],
  [APREQ2_CONFIG="$withval"],
  [with_apreq2=no]
)

AC_MSG_CHECKING([whether apreq2])
AS_IF([test "x$with_apreq2" != "xno"],
  [
   if test ! -x "${APREQ2_CONFIG}" -o -z "${APREQ2_CONFIG}"; then
     SEARCH_PATH="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
     AC_PATH_PROG(APREQ2_CONFIG, apreq2-config, no, ${SEARCH_PATH})
     AS_IF(
       [test "x${APREQ2_CONFIG}" = "xno"], AC_MSG_ERROR([apreq2-config not found]),
       [test "x${APREQ2_CONFIG}" = "x"], AC_MSG_ERROR([apreq2-config not found])
     )
   fi
   APREQ2_INCLUDES=`${APREQ2_CONFIG} --includes 2> /dev/null`
   APREQ2_LDFLAGS=`${APREQ2_CONFIG} --ldflags 2> /dev/null`
   APREQ2_LIBS=`${APREQ2_CONFIG} --libs 2> /dev/null`
   AC_MSG_RESULT(enable)
  ],
  AC_MSG_RESULT(disable)
)

# Apache libraries.
APACHE_MODULEDIR="${APXS_LIBEXECDIR}"
APACHE_INCLUDES="${APXS_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES} ${APREQ2_INCLUDES}"
APACHE_CFLAGS="${APXS_CFLAGS} ${APR_CFLAGS} ${APU_CFLAGS}"
APACHE_CPPFLAGS="${APXS_CPPFLAGS} ${APR_CPPFLAGS} ${APU_CPPFLAGS}"
APACHE_LDFLAGS="${APXS_LDFLAGS} ${APR_LDFLAGS} ${APU_LDFLAGS} ${APREQ2_LDFLAGS}"
APACHE_LIBS="${APXS_LIBS} ${APR_LIBS} ${APU_LIBS} ${APREQ2_LIBS}"

AC_SUBST(APACHE_MODULEDIR)
AC_SUBST(APACHE_INCLUDES)
AC_SUBST(APACHE_CFLAGS)
AC_SUBST(APACHE_CPPFLAGS)
AC_SUBST(APACHE_LDFLAGS)
AC_SUBST(APACHE_LIBS)


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
