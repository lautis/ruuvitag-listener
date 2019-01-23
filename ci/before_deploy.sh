#!/bin/sh

set -ex

main() {
    local src=$(pwd) \
          stage=

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    test -f Cargo.lock || cargo generate-lockfile

    cross build --target $TARGET --release
    cp target/$TARGET/release/ruuvitag-listener $stage/
    $(dirname $(readlink -f "$0"))/fpm.sh target/$TARGET/release/ruuvitag-listener

    cd $stage
    mkdir -p $src/output
    tar czf $src/output/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
    cd $src

    rm -rf $stage
}

main
