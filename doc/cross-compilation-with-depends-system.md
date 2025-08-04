CROSS COMPILATION BUILD NOTES
====================

Below are some notes on how to build Yacoin Core for Linux, Windows, and macOS using the depends system.

These notes use Ubuntu 16.04 Docker to build executables for Linux, and Ubuntu 18.04 Docker to build executables for Windows and macOS.

# Building for Linux

To ensure compatibility across different Linux distribution versions, determine the minimum glibc version that the build should support. Then, choose the Ubuntu version that corresponds to that minimum glibc version for building the executables.

For example, if the build requires a minimum glibc version of 2.23, it corresponds to Ubuntu 16.04. In this case, use Ubuntu 16.04 to build the executables. This approach ensures that the build will also work properly on Linux distributions with higher glibc versions. In the example, the build will run correctly on Ubuntu 16.04 and later.

The following steps use Ubuntu 16.04 Docker and the depends system to build the executables for Linux. The resulting executables will run properly on Ubuntu 16.04 and later versions without requiring any additional dependencies.

After running Ubuntu 16.04 Docker, do following commands to install necessary package
```
apt update
apt install -y \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  curl git ca-certificates \
  python3 g++ gperf zip unzip \
  qtbase5-dev qttools5-dev-tools qttools5-dev \
  g++-multilib python3-setuptools
```

Build the dependencies using the depends system
```
cd depends
make -j 4 HOST=x86_64-pc-linux-gnu
```

Configure the source code to use the built dependencies
```
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --enable-glibc-back-compat --enable-reduce-exports LDFLAGS=-static-libstdc++ --prefix=/
```

Build yacoind and yacoin-qt
```
make -j 4
make install DESTDIR=`pwd`/release-root
```

After building, the executables are in release-root/bin directory 

# Building for Windows

The following steps use Ubuntu 18.04 Docker and the depends system to build the executables for 64-bit Windows

After running Ubuntu 18.04 Docker, do following commands to install necessary package
```
apt update
apt install -y \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils \
  curl git ca-certificates \
  python3 g++ gperf zip unzip \
  qtbase5-dev qttools5-dev-tools qttools5-dev \
  g++-multilib \
  python3-setuptools python3-distutils \
  g++-mingw-w64-x86-64 mingw-w64-x86-64-dev
```

Run below two commands to select the 'posix' variant for the toolchain, to work around issues with mingw-w64
```
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
```

Build the dependencies using the depends system
```
cd depends
make -j 4 HOST=x86_64-w64-mingw32
```

Configure the source code to use the built dependencies
```
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure LDFLAGS=-static-libstdc++ --prefix=/
```

Build yacoind and yacoin-qt
```
make -j 4
make install DESTDIR=`pwd`/release-root
```

After building, the executables are in release-root/bin directory 


# Building for MacOS

The following steps use Ubuntu 18.04 Docker and the depends system to build the executables for MacOS

After running Ubuntu 18.04 Docker, do following commands to install necessary package
```
apt update
apt install -y build-essential bison flex autotools-dev automake pkg-config bsdmainutils  ca-certificates g++ gperf libtool libssl-dev libbz2-dev zlib1g-dev libtinfo-dev curl git python3 unzip patch wget qtbase5-dev qttools5-dev-tools qttools5-dev g++-multilib python3-setuptools python3-distutils python3-pip python-pip libcap-dev clang make libssl-dev liblzma-dev libxml2-dev cpio software-properties-common
```

Install cmake
```
wget https://apt.kitware.com/keys/kitware-archive-latest.asc
apt-key add kitware-archive-latest.asc
apt-add-repository 'https://apt.kitware.com/ubuntu/'
apt update
apt install cmake
```

Get the osxcross source code to build the toolchain used for compiling the yacoind/yacoin-qt
```
git clone https://github.com/tpoechtrager/osxcross
```

Get the MacOSX 10.11 SDK and place it in the `tarballs` directory of the osxcross source code
```
cd osxcross/tarballs/
wget https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX10.11.sdk.tar.xz
```

Build toolchain
```
cd../
UNATTENDED=1 OSX_VERSION_MIN=10.8 ./build.sh
```

Export toolchain variables
```
export PATH=$PWD/target/bin:$PATH
export OSXCROSS_NO_INCLUDE_PATH_WARNINGS=1
export SDK_VERSION=10.11
export SDK_PATH=$PWD/target/SDK
```

Go to yacoin source code and build the dependencies using the depends system and the MacOSX 10.11 SDK
```
cd <yacoin_source_path>/depends
make -j 4 HOST=x86_64-apple-darwin15
```

Configure the yacoin source code to use the built dependencies
```
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-apple-darwin15/share/config.site ./configure LDFLAGS=-static-libstdc++ --prefix=/
```

Build yacoind and yacoin-qt
```
make -j 4
make install DESTDIR=`pwd`/release-root
```

After building, the executables are in release-root/bin directory 

