#!/bin/sh

rm -rf autom4te.cache aclocal.m4 configure config.h.in config.status Makefile.in

# autotools 파일 준비
aclocal
autoheader
autoconf
automake --add-missing

# 빌드 환경 설정 및 Makefile 생성
./configure 

# 빌드
make