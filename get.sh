#!/usr/bin/env bash

: '
    Copyright (C) 2020 IBM Corporation

    Rafael Sene <rpsene@br.ibm.com> - Initial implementation.

    This is a helper script that eases the dependency setup and 
    configuration for the pvsadm tool. 
'

: '
 Usage ./get.sh
 Examples:
   # Download the latest released version of pvsadm tool
   ./get.sh

   # Download the 0.1 release
   VERSION=0.1 ./get.sh

   # Run script via curl + bash
   curl -sL https://raw.githubusercontent.com/ppc64le-cloud/pvsadm/main/get.sh | bash

   # Run script via curl + bash, replace if any existing version exist in the /usr/local/bin path
   curl -sL https://raw.githubusercontent.com/ppc64le-cloud/pvsadm/main/get.sh | FORCE=1 bash
'

# Trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
    echo "Bye!"
}

VERSION=${VERSION:=latest}
FORCE=${FORCE:=0}

function identify_os() {

    local OS="$(uname -s)"

    case "${OS}" in
        Linux*)     DISTRO=linux;;
        Darwin*)    DISTRO=darwin;;
        Catalina*)  DISTRO=darwin;;
        *)          DISTRO="UNKNOWN:${OS}"
    esac

    ARCH=$(uname -m)

    if [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ]; then
        ARCH=amd64
    fi

    export ARCH
    export DISTRO
}

function check_connectivity() {
    
    if ! curl --output /dev/null --silent --head --fail http://github.com; then
        echo
        echo "ERROR: unable to reach github.com, please check your internet connection."
        exit 1
    fi
}

function install_pvsadm() {

    local major=0
    local minor=0
    local patch=0

    if [[ "$VERSION" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        patch=${BASH_REMATCH[3]}
    fi

    if [[ "${FORCE}" -eq 1 ]]; then
       if command -v "pvsadm" &> /dev/null; then
           rm -f /usr/local/bin/pvsadm
       fi
    fi

    if command -v "pvsadm" &> /dev/null; then
        echo "pvsadm is already installed!"
        print_version $major $minor $patch
        exit 1
    fi

    if [[ "${VERSION}" == "latest" ]]; then
        DL_URL="https://github.com/ppc64le-cloud/pvsadm/releases/latest/download"
    else
        DL_URL="https://github.com/ppc64le-cloud/pvsadm/releases/download/${VERSION}"
    fi

    if ! curl --fail --progress-bar -LJ "${DL_URL}/pvsadm-$DISTRO-$ARCH" --output /usr/local/bin/pvsadm; then
        echo "Failed to download the pvsadm with mentioned ${VERSION} version, please check the VERSION"
        exit 1
    fi

    chmod +x /usr/local/bin/pvsadm
    print_version $major $minor $patch
}

function print_version() {
    # check if version is < 0.1.17, which uses the pvsadm subcommand
    local major=$1
    local minor=$2
    local patch=$3
    if [ $major -lt 1 ] && [ $minor -lt 2 ] && [ $patch -lt 17 ];
    then
        pvsadm version
    # the more recent releases support the version flag
    else
        pvsadm --version
    fi
}

function run (){

    if [[ "${FORCE}" -ne 1 ]]; then
       echo
       echo "To replace an old version of pvsadm, run this script with an environment variable: FORCE=1"
       echo
    fi

    identify_os
    check_connectivity
    install_pvsadm
}

run
