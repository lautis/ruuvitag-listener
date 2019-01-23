#!/bin/sh

set -ex

# TODO This is the "test phase", tweak it as you see fit
main() {
    cross build --target $TARGET --locked
    cross build --target $TARGET --release --locked

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET --locked
    cross test --target $TARGET --release --locked
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
