#!/bin/sh

#
# SETTINGS.BEGIN
#

# Set PREFIX if the environment did not offer it
PREFIX=${PREFIX-../PREFIX}

#
# SETTINGS.END
#



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #



# Work relative to this script's directory
#
cd $(dirname "$0")


# Check settings
#

echo 'Installation settings:'
echo 'PREFIX="'"$PREFIX"'"'
case "$PREFIX" in
/*)
	;;
*)
	echo 'This prefix is relative to "'"$PWD"'"'
esac
echo
echo -n 'Is this okay? '

read OK
case $OK in
y*|Y*)
	;;
n*|N*)
	echo 'Please set $PREFIX or edit this script and try again'
	exit 1
	;;
*)
	echo 'Inconclusive answer.  Exiting.'
	exit 1
esac


# Create directories
#
mkdir -p "$PREFIX" "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/doc"


# Install the rabbitdnssec.py library
#
echo cp -p lib/rabbitdnssec.py "$PREFIX/lib"
     cp -p lib/rabbitdnssec.py "$PREFIX/lib"


# Install main-directory documentation
#
ls -1 README* readme* *.md *.MD *.txt *.TXT man doc/* 2>/dev/null | \
	sort | uniq | \
	while read f
	do
		echo cp -p "$f" "$PREFIX/doc"
		     cp -p "$f" "$PREFIX/doc"
	done


# Install commands and libraries
#
for d in ods-*
do
	for f in "$d"/*
	do
		case "$f" in
		*.py|*.pyc|*.pyo)
			mkdir -p "$PREFIX/lib/$d"
			echo cp -p "$f" "$PREFIX/lib/$d"
			     cp -p "$f" "$PREFIX/lib/$d"
			;;
		README*|readme*|*.md|*.MD|*.txt|*.TXT)
			mkdir -p "$PREFIX/doc/$d"
			echo cp -p "$f" "$PREFIX/doc/$d"
			     cp -p "$f" "$PREFIX/doc/$d"
			;;
		*)
			echo cp -p "$f" "$PREFIX/bin"
			     cp -p "$f" "$PREFIX/bin"
		esac
	done
done


# Report done (and further instructions)
#
echo
echo 'Script installation done.  You also need to setup RabbitMQ.'
echo
echo 'You can now setup accounts with configurations for the scripts.'
echo
echo 'Binaries  need       PATH="$PATH:'"$PREFIX"'/bin"'
echo 'Libraries need PYTHONPATH="$PYTHONPATH:'"$PREFIX"'/lib"'
echo

