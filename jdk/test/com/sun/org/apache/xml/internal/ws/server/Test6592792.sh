#!/bin/sh

if [ "${TESTSRC}" = "" ]
then TESTSRC=.
fi

if [ "${TESTJAVA}" = "" ]
then
  PARENT=`dirname \`which java\``
  TESTJAVA=`dirname ${PARENT}`
  echo "TESTJAVA not set, selecting " ${TESTJAVA}
  echo "If this is incorrect, try setting the variable manually."
fi

if [ "${TESTCLASSES}" = "" ]
then
  echo "TESTCLASSES not set.  Test cannot execute.  Failed."
  exit 1
fi

BIT_FLAG=""

# set platform-dependent variables
OS=`uname -s`
case "$OS" in
  SunOS | Linux )
    NULL=/dev/null
    PS=":"
    FS="/"
    ## for solaris, linux it's HOME
    FILE_LOCATION=$HOME
    if [ -f ${FILE_LOCATION}${FS}JDK64BIT -a ${OS} = "SunOS" ]
    then
        BIT_FLAG=`cat ${FILE_LOCATION}${FS}JDK64BIT`
    fi
    ;;
  Windows_* )
    NULL=NUL
    PS=";"
    FS="\\"
    ;;
  * )
    echo "Unrecognized system!"
    exit 1;
    ;;
esac

JEMMYPATH=${CPAPPEND}
CLASSPATH=.${PS}${TESTCLASSES}${PS}${JEMMYPATH} ; export CLASSPATH

THIS_DIR=`pwd`

${TESTJAVA}${FS}bin${FS}java ${BIT_FLAG} -version

# the package com.sun.xml.internal.ws.server rt.jar is filtered by the symbol 
# file; so ignore it
${TESTJAVA}${FS}bin${FS}javac ${BIT_FLAG} -XDignore.symbol.file=true -d . ${TESTSRC}${FS}Test.java

${TESTJAVA}${FS}bin${FS}java ${BIT_FLAG} -cp . Test

STATUS=$?

exit $STATUS
