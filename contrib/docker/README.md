# Dockerfiles

## Ubuntu build

The Dockerfiles provide a Ubuntu build environment and will run a build.

In order to build the Ubuntu 16.04 build environment run:

    docker build -t yacoin-build:ubuntu.1604 -f Dockerfile.ubuntu.16.04 .

In order to build the Ubuntu 18.04 build environment run:

    docker build -t yacoin-build:ubuntu.1804 -f Dockerfile.ubuntu.18.04 .

In order to apply the build environment to a yacoin folder:

    docker run -v <Absolute Path to yacoin folder>:/src --user $UID:$GID yacoin-build:ubuntu.1804

The built yacoind and yacoin-qt will then be available after the build is done in the host system.

In order to build a Docker container with yacoind and yacoin-qt in it:

    docker build -t yacoin:latest -f Dockerfile.yacoin ../../

In order to run yacoind from the container:

    docker run -v <Absolute path to yacoin datadir>:/data --user $UID:$GID yacoin:latest

In order to run yacoin-qt from the container:

    docker run --rm -e QT_GRAPHICSSYSTEM="native" -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v <Absolute path to yacoin data dir>:/data --user $UID:$GID yacoin:latest /yacoin-qt -datadir=/data
