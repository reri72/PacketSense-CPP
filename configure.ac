#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([PacketSense-CPP], [1.0.0], [reri0702@gmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_SRCDIR([src/main.cpp])
AC_CONFIG_HEADERS([config.h])

AM_PROG_AR

# Checks for programs.
AC_LANG([C++])
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live],
    [PCAP_LIBS="-lpcap"],
    [AC_MSG_ERROR([libpacp (Development files) not found.])]
)
AC_SUBST(PCAP_LIBS)

AC_CHECK_LIB([sqlite3], [sqlite3_open],
    [SQLITE3_LIBS="-lsqlite3"],
    [AC_MSG_ERROR([libsqlite3 (Development files) not found.])]
)
AC_SUBST(SQLITE3_LIBS)

AC_CHECK_LIB([pthread], [pthread_create], [PTHREAD_LIBS="-pthread"], [])
AC_SUBST(PTHREAD_LIBS)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([socket])

AC_OUTPUT([Makefile])
