#!/bin/bash

set -x

# Do make sure Jenkins is checking out to a sub directory in relative to PWD
# "src/github.com/loomnetwork/transfer-gateway"
# it's a config option

PKG=github.com/loomnetwork/transfer-gateway
LOOMCHAIN_PKG=github.com/loomnetwork/loomchain

# Setup GOPATH and PATH
export GOPATH=`pwd`
export PATH=$GOPATH:$PATH:/var/lib/jenkins/workspace/commongopath/bin:$GOPATH/bin

# Clone loomchain
rm -rf $GOPATH/src/$LOOMCHAIN_PKG
git clone git@github.com:loomnetwork/loomchain.git $GOPATH/src/$LOOMCHAIN_PKG

# Get into the source tree to build
cd $GOPATH/src/$PKG

# Run the build
make deps
make test
