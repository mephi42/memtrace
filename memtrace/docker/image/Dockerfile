ARG repo=quay.io/pypa
ARG arch=x86_64
ARG version=2020-05-25-6481506
ARG capstone_version=4.0.1
ARG boost_version=1_73_0
FROM ${repo}/manylinux2010_${arch}:${version} AS base

FROM base AS boost
ARG boost_version
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -L https://dl.bintray.com/boostorg/release/"$(echo ${boost_version} | tr _ .)"/source/boost_${boost_version}.tar.bz2 | tar -C /usr/src -xjv
WORKDIR /usr/src/boost_${boost_version}
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

FROM base
RUN yum install -y \
    elfutils \
    libgcc.i686 \
    ninja-build
RUN yum remove -y cmake cmake28
RUN cd /tmp && \
    curl -L https://github.com/Kitware/CMake/archive/v3.11.4.tar.gz | tar -xvz && \
    cd CMake-3.11.4 && \
    ./configure --prefix=/usr --parallel=$(getconf _NPROCESSORS_ONLN) && \
    make -j$(getconf _NPROCESSORS_ONLN) && \
    make install -j$(getconf _NPROCESSORS_ONLN) && \
    cd /tmp && \
    rm -r CMake-3.11.4
COPY --from=capstone /opt/capstone/ /
COPY --from=boost /opt/boost/ /
