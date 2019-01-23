#!/bin/sh
set -e

BASEDIR=$(dirname $(dirname $(readlink -f "$0")))
OUTPUTDIR=$BASEDIR/output
TMPDIR=$BASEDIR/tmp
USRDIR=$TMPDIR/usr
BINDIR=$USRDIR/bin
LICDIR=$USRDIR/share/licenses/ruuvitag-listener

umask 022
rm -rf $OUTPUTDIR $USRDIR
mkdir -p $OUTPUTDIR $BINDIR $USRDIR $LICDIR

typeset -a CARGS=(
  --architecture $(cut -d'-' -f1 <<< $TARGET)
  --input-type dir
  --name "$(rq -t 'at "package.name"' < $BASEDIR/Cargo.toml | sed -e 's/^"//' -e 's/"$//')"
  --license "$(rq -t 'at "package.license"' < $BASEDIR/Cargo.toml | sed -e 's/^"//' -e 's/"$//')"
  --version "$(rq -t 'at "package.version"' < $BASEDIR/Cargo.toml | sed -e 's/^"//' -e 's/"$//')"
  --description "$(rq -t 'at "package.description"' < $BASEDIR/Cargo.toml | sed -e 's/^"//' -e 's/"$//')"
  --maintainer "$(rq -t 'at "package.authors[0]"' < $BASEDIR/Cargo.toml | sed -e 's/^"//' -e 's/"$//')"
  --deb-no-default-config-files
  --url "$(rq -t 'at "package.repository"' < $BASEDIR/Cargo.toml)"
  --depends "bluez"
  --chdir $TMPDIR
  --package $OUTPUTDIR
  --after-install $BASEDIR/ci/after_install.sh
)

typeset -a DIRS=( usr )

mkdir -p target/fpm
cp $1 $BINDIR
cp LICENSE.txt $LICDIR/LICENSE

echo ${CARGS[@]} ${DIRS[@]}

(cd $BASEDIR && fpm -t pacman "${CARGS[@]}" "${DIRS[@]}")
(cd $BASEDIR && fpm -t deb "${CARGS[@]}" "${DIRS[@]}")
