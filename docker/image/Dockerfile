ARG base
ARG capstone_version=4.0.1
ARG boost_version=1_73_0
ARG cmake_version=3.11.4
ARG ninja_version=1.10.0
ARG quilt_version=0.66
ARG ccache_version=3.7.12
FROM ${base} AS base

FROM base AS boost
ARG boost_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://dl.bintray.com/boostorg/release/"$(echo ${boost_version} | tr _ .)"/source/boost_${boost_version}.tar.bz2 | tar -C /usr/src -xjv
WORKDIR /usr/src/boost_${boost_version}
COPY CXXABI_LDBL.patch .
RUN patch -p1 -d libs/python <CXXABI_LDBL.patch
RUN ./bootstrap.sh
COPY user-config.jam tools/build/src/
RUN ./b2 cxxflags=-fPIC --with-python python=3.6,3.7,3.8 variant=release link=static threading=multi runtime-link=shared --prefix=/opt/boost/usr install

FROM base AS capstone
ARG capstone_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://github.com/aquynh/capstone/archive/${capstone_version}.tar.gz | tar -C /usr/src -xzv
WORKDIR /usr/src/capstone-${capstone_version}
ENV CAPSTONE_STATIC=yes
ENV CAPSTONE_SHARED=no
RUN make
RUN make install DESTDIR=/opt/capstone

FROM base as cmake
ARG cmake_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://github.com/Kitware/CMake/archive/v${cmake_version}.tar.gz | tar -C /usr/src -xvz
WORKDIR /usr/src/CMake-${cmake_version}
RUN ./configure --prefix=/usr --parallel="$(getconf _NPROCESSORS_ONLN)"
RUN make -j"$(getconf _NPROCESSORS_ONLN)"
RUN make install DESTDIR=/opt/cmake

FROM base as ninja
ARG ninja_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://github.com/ninja-build/ninja/archive/v${ninja_version}.tar.gz | tar -C /usr/src -xvz
WORKDIR /usr/src/ninja-${ninja_version}
RUN ./configure.py --bootstrap
RUN mkdir -p /opt/ninja/usr/bin
RUN cp ninja /opt/ninja/usr/bin/

FROM base as quilt
ARG quilt_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L http://download.savannah.gnu.org/releases/quilt/quilt-${quilt_version}.tar.gz | tar -C /usr/src -xvz
WORKDIR /usr/src/quilt-${quilt_version}
# quilt's build system does not support DESTDIR
RUN ./configure --prefix=/opt/quilt
RUN make -j"$(getconf _NPROCESSORS_ONLN)"
RUN make install

FROM base as ccache
ARG ccache_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://github.com/ccache/ccache/releases/download/v${ccache_version}/ccache-${ccache_version}.tar.xz | tar -C /usr/src -xvJ
WORKDIR /usr/src/ccache-${ccache_version}
RUN ./configure --prefix=/opt/ccache
RUN make -j"$(getconf _NPROCESSORS_ONLN)"
RUN make install

FROM base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN yum install -y \
    elfutils \
    $([ "$(uname -m)" != "x86_64" ] || echo glibc-devel.i686 libgcc.i686)
RUN yum remove -y cmake cmake28
COPY --from=boost /opt/boost/ /
COPY --from=capstone /opt/capstone/ /
COPY --from=cmake /opt/cmake/ /
COPY --from=ninja /opt/ninja/ /
COPY --from=quilt /opt/quilt/ /opt/quilt/
RUN ln -s /opt/quilt/bin/quilt /usr/bin/quilt
COPY --from=ccache /opt/ccache/ /opt/ccache/
RUN ln -s ccache /opt/ccache/bin/c++
RUN ln -s ccache /opt/ccache/bin/cc
RUN ln -s ccache /opt/ccache/bin/gcc
RUN ln -s ccache /opt/ccache/bin/g++
ENV PATH=/opt/ccache/bin:$PATH
