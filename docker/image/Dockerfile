# https://github.com/benfogle/crossenv
# https://github.com/rust-cross/manylinux-cross

ARG boost_version=1_85_0
ARG capstone_version=4.0.2
ARG crosstool_ng_version=1.26.0
ARG elfutils_version=0.188
ARG systemtap_version=5.2
ARG zlib_ng_version=2.2.3

# https://hub.docker.com/_/debian/tags?page=&page_size=&ordering=&name=bookworm
FROM debian:bookworm-20250113-slim AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

FROM base AS crosstool-ng-base
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autoconf \
        automake \
        bison \
        bzip2 \
        ca-certificates \
        curl \
        file \
        flex \
        g++ \
        gawk \
        gcc \
        git \
        help2man \
        libncurses-dev \
        libstdc++-12-dev \
        libtool-bin \
        make \
        patch \
        texinfo \
        unzip \
        xz-utils
ARG crosstool_ng_version
RUN git clone \
        --branch=crosstool-ng-${crosstool_ng_version} \
        --depth=1 \
        https://github.com/crosstool-ng/crosstool-ng.git \
        /usr/src/crosstool-ng
WORKDIR /usr/src/crosstool-ng
RUN ./bootstrap
RUN ./configure
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-base AS crosstool-ng-aarch64
WORKDIR /usr/src
RUN mkdir crosstool-ng-aarch64
WORKDIR crosstool-ng-aarch64
COPY crosstool-ng/common .
COPY crosstool-ng/aarch64 .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/aarch64-unknown-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-arm
WORKDIR /usr/src
RUN mkdir crosstool-ng-arm
WORKDIR crosstool-ng-arm
COPY crosstool-ng/common .
COPY crosstool-ng/arm .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/arm-unknown-linux-gnueabihf/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-i686
WORKDIR /usr/src
RUN mkdir crosstool-ng-i686
WORKDIR crosstool-ng-i686
COPY crosstool-ng/common .
COPY crosstool-ng/i686 .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/i686-unknown-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-ppc64
WORKDIR /usr/src
RUN mkdir crosstool-ng-ppc64
WORKDIR crosstool-ng-ppc64
COPY crosstool-ng/common .
COPY crosstool-ng/ppc64 .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/powerpc64-unknown-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-ppc64le
WORKDIR /usr/src
RUN mkdir crosstool-ng-ppc64le
WORKDIR crosstool-ng-ppc64le
COPY crosstool-ng/common .
COPY crosstool-ng/ppc64le .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/powerpc64le-unknown-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-s390x
WORKDIR /usr/src
RUN mkdir crosstool-ng-s390x
WORKDIR crosstool-ng-s390x
COPY crosstool-ng/common .
COPY crosstool-ng/s390x .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/s390x-ibm-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS crosstool-ng-x86_64
WORKDIR /usr/src
RUN mkdir crosstool-ng-x86_64
WORKDIR crosstool-ng-x86_64
COPY crosstool-ng/common .
COPY crosstool-ng/x86_64 .
RUN cat common.config arch.config >.config
RUN ct-ng olddefconfig
ENV CT_ALLOW_BUILD_AS_ROOT_SURE=1
RUN ct-ng source
RUN ct-ng build || { err=$?; tail -n 500 build.log; exit $err; }
ENV PATH=/usr/x86_64-unknown-linux-gnu/bin:$PATH
# https://stackoverflow.com/questions/77895008
RUN apt-get remove --yes libc6-dev

FROM crosstool-ng-base AS cp36-cp36m
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.6.15 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp36-cp36m
WORKDIR /usr/src/cp36-cp36m
RUN git -c user.name=mephi42 -c user.email=mephi42@gmail.com cherry-pick f0be4bbb9b3c 8766cb74e186 6e5a193816e1
WORKDIR /tmp/cp36-cp36m-build
RUN /usr/src/cp36-cp36m/configure \
        --prefix=/opt/cp36-cp36m \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp36-cp36m/bin/python3

FROM crosstool-ng-base AS cp37-cp37m
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.7.17 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp37-cp37m
WORKDIR /usr/src/cp37-cp37m
RUN git -c user.name=mephi42 -c user.email=mephi42@gmail.com cherry-pick 6e5a193816e1
WORKDIR /tmp/cp37-cp37m-build
RUN /usr/src/cp37-cp37m/configure \
        --prefix=/opt/cp37-cp37m \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp37-cp37m/bin/python3

FROM crosstool-ng-base AS cp38-cp38
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.8.20 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp38-cp38
WORKDIR /usr/src/cp38-cp38
RUN git -c user.name=mephi42 -c user.email=mephi42@gmail.com cherry-pick 6e5a193816e1
WORKDIR /tmp/cp38-cp38-build
RUN /usr/src/cp38-cp38/configure \
        --prefix=/opt/cp38-cp38 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp38-cp38/bin/python3

FROM crosstool-ng-base AS cp39-cp39
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.9.21 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp39-cp39
WORKDIR /usr/src/cp39-cp39
RUN git -c user.name=mephi42 -c user.email=mephi42@gmail.com cherry-pick 6e5a193816e1
WORKDIR /tmp/cp39-cp39-build
RUN /usr/src/cp39-cp39/configure \
        --prefix=/opt/cp39-cp39 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp39-cp39/bin/python3

FROM crosstool-ng-base AS cp310-cp310
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.10.16 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp310-cp310
WORKDIR /usr/src/cp310-cp310
RUN git -c user.name=mephi42 -c user.email=mephi42@gmail.com cherry-pick 6e5a193816e1
WORKDIR /tmp/cp310-cp310-build
RUN /usr/src/cp310-cp310/configure \
        --prefix=/opt/cp310-cp310 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp310-cp310/bin/python3

FROM crosstool-ng-base AS cp311-cp311
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.11.11 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp311-cp311
WORKDIR /usr/src/cp311-cp311
WORKDIR /tmp/cp311-cp311-build
RUN /usr/src/cp311-cp311/configure \
        --prefix=/opt/cp311-cp311 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp311-cp311/bin/python3

FROM crosstool-ng-base AS cp312-cp312
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.12.8 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp312-cp312
WORKDIR /usr/src/cp312-cp312
WORKDIR /tmp/cp312-cp312-build
RUN /usr/src/cp312-cp312/configure \
        --prefix=/opt/cp312-cp312 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp312-cp312/bin/python3

FROM crosstool-ng-base AS cp313-cp313
RUN apt-get update && apt-get install --no-install-recommends --yes \
        libffi-dev \
        libssl-dev \
        patchelf \
        zlib1g-dev
RUN git clone \
        --branch=v3.13.1 \
        --filter=tree:0 \
        https://github.com/python/cpython.git \
        /usr/src/cp313-cp313
WORKDIR /usr/src/cp313-cp313
WORKDIR /tmp/cp313-cp313-build
RUN /usr/src/cp313-cp313/configure \
        --prefix=/opt/cp313-cp313 \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install
RUN patchelf --set-rpath '$ORIGIN/../lib' /opt/cp313-cp313/bin/python3

FROM crosstool-ng-aarch64 AS cp36-cp36m-aarch64
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp36-cp36m-arm
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp36-cp36m-i686
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp36-cp36m-ppc64
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp36-cp36m-ppc64le
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp36-cp36m-s390x
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp36-cp36m-x86_64
COPY --from=cp36-cp36m /usr/src/cp36-cp36m /usr/src/cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
ENV PATH=/opt/cp36-cp36m/bin:$PATH
WORKDIR /usr/src/cp36-cp36m
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp36-cp36m \
        --with-build-python=/opt/cp36-cp36m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp37-cp37m-aarch64
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp37-cp37m-arm
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp37-cp37m-i686
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp37-cp37m-ppc64
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp37-cp37m-ppc64le
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp37-cp37m-s390x
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp37-cp37m-x86_64
COPY --from=cp37-cp37m /usr/src/cp37-cp37m /usr/src/cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
ENV PATH=/opt/cp37-cp37m/bin:$PATH
WORKDIR /usr/src/cp37-cp37m
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp37-cp37m \
        --with-build-python=/opt/cp37-cp37m/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --with-pymalloc \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp38-cp38-aarch64
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp38-cp38-arm
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp38-cp38-i686
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp38-cp38-ppc64
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp38-cp38-ppc64le
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp38-cp38-s390x
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp38-cp38-x86_64
COPY --from=cp38-cp38 /usr/src/cp38-cp38 /usr/src/cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
ENV PATH=/opt/cp38-cp38/bin:$PATH
WORKDIR /usr/src/cp38-cp38
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp38-cp38 \
        --with-build-python=/opt/cp38-cp38/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp39-cp39-aarch64
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp39-cp39-arm
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp39-cp39-i686
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp39-cp39-ppc64
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp39-cp39-ppc64le
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp39-cp39-s390x
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp39-cp39-x86_64
COPY --from=cp39-cp39 /usr/src/cp39-cp39 /usr/src/cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
ENV PATH=/opt/cp39-cp39/bin:$PATH
WORKDIR /usr/src/cp39-cp39
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp39-cp39 \
        --with-build-python=/opt/cp39-cp39/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp310-cp310-aarch64
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp310-cp310-arm
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp310-cp310-i686
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp310-cp310-ppc64
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp310-cp310-ppc64le
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp310-cp310-s390x
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp310-cp310-x86_64
COPY --from=cp310-cp310 /usr/src/cp310-cp310 /usr/src/cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
ENV PATH=/opt/cp310-cp310/bin:$PATH
WORKDIR /usr/src/cp310-cp310
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp310-cp310 \
        --with-build-python=/opt/cp310-cp310/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp311-cp311-aarch64
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp311-cp311-arm
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp311-cp311-i686
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp311-cp311-ppc64
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp311-cp311-ppc64le
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp311-cp311-s390x
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp311-cp311-x86_64
COPY --from=cp311-cp311 /usr/src/cp311-cp311 /usr/src/cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
ENV PATH=/opt/cp311-cp311/bin:$PATH
WORKDIR /usr/src/cp311-cp311
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp311-cp311 \
        --with-build-python=/opt/cp311-cp311/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp312-cp312-aarch64
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp312-cp312-arm
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp312-cp312-i686
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp312-cp312-ppc64
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp312-cp312-ppc64le
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp312-cp312-s390x
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp312-cp312-x86_64
COPY --from=cp312-cp312 /usr/src/cp312-cp312 /usr/src/cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
ENV PATH=/opt/cp312-cp312/bin:$PATH
WORKDIR /usr/src/cp312-cp312
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp312-cp312 \
        --with-build-python=/opt/cp312-cp312/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-aarch64 AS cp313-cp313-aarch64
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-arm AS cp313-cp313-arm
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-i686 AS cp313-cp313-i686
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64 AS cp313-cp313-ppc64
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-ppc64le AS cp313-cp313-ppc64le
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-s390x AS cp313-cp313-s390x
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM crosstool-ng-x86_64 AS cp313-cp313-x86_64
COPY --from=cp313-cp313 /usr/src/cp313-cp313 /usr/src/cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
ENV PATH=/opt/cp313-cp313/bin:$PATH
WORKDIR /usr/src/cp313-cp313
RUN ./configure \
        --build="$(uname -m)" \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/cp313-cp313 \
        --with-build-python=/opt/cp313-cp313/bin/python3 \
        ac_cv_buggy_getaddrinfo=no \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        --enable-shared
RUN make "-j$(getconf _NPROCESSORS_ONLN)"
RUN make "-j$(getconf _NPROCESSORS_ONLN)" install

FROM base AS boost-base
RUN apt-get update && apt-get install --no-install-recommends --yes \
        ca-certificates \
        bzip2 \
        curl \
        g++ \
        patch
ARG boost_version
RUN curl -L https://archives.boost.io/release/$(echo ${boost_version} | tr _ .)/source/boost_${boost_version}.tar.bz2 | tar -C /usr/src -xjv
RUN mv /usr/src/boost_${boost_version} /usr/src/boost
WORKDIR /usr/src/boost
RUN ./bootstrap.sh || { err=$?; tail -n 500 bootstrap.log; exit $err; }
COPY boost/common .
RUN patch -p1 -d libs/python <CXXABI_LDBL.patch

FROM crosstool-ng-aarch64 AS boost-aarch64
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp36-cp36m \
     /usr/aarch64-unknown-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp37-cp37m \
     /usr/aarch64-unknown-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp38-cp38 \
     /usr/aarch64-unknown-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp39-cp39 \
     /usr/aarch64-unknown-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp310-cp310 \
     /usr/aarch64-unknown-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp311-cp311 \
     /usr/aarch64-unknown-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp312-cp312 \
     /usr/aarch64-unknown-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp313-cp313 \
     /usr/aarch64-unknown-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/aarch64 .
RUN ./b2 \
        --prefix=/opt/boost-aarch64/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-aarch64 \
        variant=release \
        install

FROM crosstool-ng-arm AS boost-arm
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-arm \
     /usr/arm-unknown-linux-gnueabihf/cp36-cp36m \
     /usr/arm-unknown-linux-gnueabihf/cp36-cp36m
COPY --from=cp37-cp37m-arm \
     /usr/arm-unknown-linux-gnueabihf/cp37-cp37m \
     /usr/arm-unknown-linux-gnueabihf/cp37-cp37m
COPY --from=cp38-cp38-arm \
     /usr/arm-unknown-linux-gnueabihf/cp38-cp38 \
     /usr/arm-unknown-linux-gnueabihf/cp38-cp38
COPY --from=cp39-cp39-arm \
     /usr/arm-unknown-linux-gnueabihf/cp39-cp39 \
     /usr/arm-unknown-linux-gnueabihf/cp39-cp39
COPY --from=cp310-cp310-arm \
     /usr/arm-unknown-linux-gnueabihf/cp310-cp310 \
     /usr/arm-unknown-linux-gnueabihf/cp310-cp310
COPY --from=cp311-cp311-arm \
     /usr/arm-unknown-linux-gnueabihf/cp311-cp311 \
     /usr/arm-unknown-linux-gnueabihf/cp311-cp311
COPY --from=cp312-cp312-arm \
     /usr/arm-unknown-linux-gnueabihf/cp312-cp312 \
     /usr/arm-unknown-linux-gnueabihf/cp312-cp312
COPY --from=cp313-cp313-arm \
     /usr/arm-unknown-linux-gnueabihf/cp313-cp313 \
     /usr/arm-unknown-linux-gnueabihf/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/arm .
RUN ./b2 \
        --prefix=/opt/boost-arm/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-arm \
        variant=release \
        install

FROM crosstool-ng-i686 AS boost-i686
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-i686 \
     /usr/i686-unknown-linux-gnu/cp36-cp36m \
     /usr/i686-unknown-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-i686 \
     /usr/i686-unknown-linux-gnu/cp37-cp37m \
     /usr/i686-unknown-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-i686 \
     /usr/i686-unknown-linux-gnu/cp38-cp38 \
     /usr/i686-unknown-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-i686 \
     /usr/i686-unknown-linux-gnu/cp39-cp39 \
     /usr/i686-unknown-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-i686 \
     /usr/i686-unknown-linux-gnu/cp310-cp310 \
     /usr/i686-unknown-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-i686 \
     /usr/i686-unknown-linux-gnu/cp311-cp311 \
     /usr/i686-unknown-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-i686 \
     /usr/i686-unknown-linux-gnu/cp312-cp312 \
     /usr/i686-unknown-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-i686 \
     /usr/i686-unknown-linux-gnu/cp313-cp313 \
     /usr/i686-unknown-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/i686 .
RUN ./b2 \
        --prefix=/opt/boost-i686/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-i686 \
        variant=release \
        install

FROM crosstool-ng-ppc64 AS boost-ppc64
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp36-cp36m \
     /usr/powerpc64-unknown-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp37-cp37m \
     /usr/powerpc64-unknown-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp38-cp38 \
     /usr/powerpc64-unknown-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp39-cp39 \
     /usr/powerpc64-unknown-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp310-cp310 \
     /usr/powerpc64-unknown-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp311-cp311 \
     /usr/powerpc64-unknown-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp312-cp312 \
     /usr/powerpc64-unknown-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp313-cp313 \
     /usr/powerpc64-unknown-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/ppc64 .
RUN ./b2 \
        --prefix=/opt/boost-ppc64/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-ppc64 \
        variant=release \
        install

FROM crosstool-ng-ppc64le AS boost-ppc64le
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp36-cp36m \
     /usr/powerpc64le-unknown-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp37-cp37m \
     /usr/powerpc64le-unknown-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp38-cp38 \
     /usr/powerpc64le-unknown-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp39-cp39 \
     /usr/powerpc64le-unknown-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp310-cp310 \
     /usr/powerpc64le-unknown-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp311-cp311 \
     /usr/powerpc64le-unknown-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp312-cp312 \
     /usr/powerpc64le-unknown-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp313-cp313 \
     /usr/powerpc64le-unknown-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/ppc64le .
RUN ./b2 \
        --prefix=/opt/boost-ppc64le/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-ppc64le \
        variant=release \
        install

FROM crosstool-ng-s390x AS boost-s390x
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-s390x \
     /usr/s390x-ibm-linux-gnu/cp36-cp36m \
     /usr/s390x-ibm-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-s390x \
     /usr/s390x-ibm-linux-gnu/cp37-cp37m \
     /usr/s390x-ibm-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-s390x \
     /usr/s390x-ibm-linux-gnu/cp38-cp38 \
     /usr/s390x-ibm-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-s390x \
     /usr/s390x-ibm-linux-gnu/cp39-cp39 \
     /usr/s390x-ibm-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-s390x \
     /usr/s390x-ibm-linux-gnu/cp310-cp310 \
     /usr/s390x-ibm-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-s390x \
     /usr/s390x-ibm-linux-gnu/cp311-cp311 \
     /usr/s390x-ibm-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-s390x \
     /usr/s390x-ibm-linux-gnu/cp312-cp312 \
     /usr/s390x-ibm-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-s390x \
     /usr/s390x-ibm-linux-gnu/cp313-cp313 \
     /usr/s390x-ibm-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/s390x .
RUN ./b2 \
        --prefix=/opt/boost-s390x/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-s390x \
        variant=release \
        install

FROM crosstool-ng-x86_64 AS boost-x86_64
COPY --from=boost-base /usr/src/boost /usr/src/boost
COPY --from=cp36-cp36m-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp36-cp36m \
     /usr/x86_64-unknown-linux-gnu/cp36-cp36m
COPY --from=cp37-cp37m-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp37-cp37m \
     /usr/x86_64-unknown-linux-gnu/cp37-cp37m
COPY --from=cp38-cp38-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp38-cp38 \
     /usr/x86_64-unknown-linux-gnu/cp38-cp38
COPY --from=cp39-cp39-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp39-cp39 \
     /usr/x86_64-unknown-linux-gnu/cp39-cp39
COPY --from=cp310-cp310-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp310-cp310 \
     /usr/x86_64-unknown-linux-gnu/cp310-cp310
COPY --from=cp311-cp311-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp311-cp311 \
     /usr/x86_64-unknown-linux-gnu/cp311-cp311
COPY --from=cp312-cp312-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp312-cp312 \
     /usr/x86_64-unknown-linux-gnu/cp312-cp312
COPY --from=cp313-cp313-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp313-cp313 \
     /usr/x86_64-unknown-linux-gnu/cp313-cp313
WORKDIR /usr/src/boost
COPY boost/x86_64 .
RUN ./b2 \
        --prefix=/opt/boost-x86_64/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr \
        --with-python \
        cxxflags=-fPIC \
        link=static \
        python=3.6,3.7,3.8,3.9,3.10,3.11,3.12,3.13 \
        runtime-link=shared \
        threading=multi \
        toolset=gcc-x86_64 \
        variant=release \
        install

FROM crosstool-ng-base AS capstone-base
ARG capstone_version
RUN git clone \
        --branch=${capstone_version} \
        --depth=1 \
        https://github.com/capstone-engine/capstone.git \
        /usr/src/capstone

FROM crosstool-ng-aarch64 AS capstone-aarch64
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=aarch64-unknown-linux-gnu- \
        DESTDIR=/opt/capstone-aarch64 \
        PREFIX=/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-arm AS capstone-arm
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=arm-unknown-linux-gnueabihf- \
        DESTDIR=/opt/capstone-arm \
        PREFIX=/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-i686 AS capstone-i686
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=i686-unknown-linux-gnu- \
        DESTDIR=/opt/capstone-i686 \
        PREFIX=/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-ppc64 AS capstone-ppc64
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=powerpc64-unknown-linux-gnu- \
        DESTDIR=/opt/capstone-ppc64 \
        PREFIX=/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-ppc64le AS capstone-ppc64le
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=powerpc64le-unknown-linux-gnu- \
        DESTDIR=/opt/capstone-ppc64le \
        PREFIX=/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-s390x AS capstone-s390x
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=s390x-ibm-linux-gnu- \
        DESTDIR=/opt/capstone-s390x \
        PREFIX=/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-x86_64 AS capstone-x86_64
COPY --from=capstone-base /usr/src/capstone /usr/src/capstone
WORKDIR /usr/src/capstone
RUN make \
        CAPSTONE_BUILD_CORE_ONLY=yes \
        CAPSTONE_SHARED=no \
        CAPSTONE_STATIC=yes \
        CROSS=x86_64-unknown-linux-gnu- \
        DESTDIR=/opt/capstone-x86_64 \
        PREFIX=/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-base AS zlib-ng-base
ARG zlib_ng_version
RUN git clone \
        --branch=${zlib_ng_version} \
        --depth=1 \
        https://github.com/zlib-ng/zlib-ng.git \
        /usr/src/zlib-ng

FROM crosstool-ng-aarch64 AS zlib-ng-aarch64
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=aarch64-unknown-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-aarch64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-arm AS zlib-ng-arm
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=arm-unknown-linux-gnueabihf CFLAGS=-fPIC ./configure \
        --prefix=/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-arm \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-i686 AS zlib-ng-i686
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=i686-unknown-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-i686 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-ppc64 AS zlib-ng-ppc64
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=powerpc64-unknown-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-ppc64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-ppc64le AS zlib-ng-ppc64le
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=powerpc64le-unknown-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-ppc64le \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-s390x AS zlib-ng-s390x
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=s390x-ibm-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-s390x \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-x86_64 AS zlib-ng-x86_64
COPY --from=zlib-ng-base /usr/src/zlib-ng /usr/src/zlib-ng
WORKDIR /usr/src/zlib-ng
RUN CHOST=x86_64-unknown-linux-gnu CFLAGS=-fPIC ./configure \
        --prefix=/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr \
        --static \
        --zlib-compat
RUN make \
        DESTDIR=/opt/zlib-ng-x86_64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install

FROM crosstool-ng-base AS elfutils-base
ARG elfutils_version
RUN curl https://sourceware.org/pub/elfutils/${elfutils_version}/elfutils-${elfutils_version}.tar.bz2 | tar -C /usr/src -xjv

FROM crosstool-ng-aarch64 AS elfutils-aarch64
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-aarch64 /opt/zlib-ng-aarch64/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=aarch64-unknown-linux-gnu \
        --prefix=/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-aarch64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-aarch64/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-arm AS elfutils-arm
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-arm /opt/zlib-ng-arm/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=arm-unknown-linux-gnueabihf \
        --prefix=/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-arm \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-arm/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-i686 AS elfutils-i686
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-i686 /opt/zlib-ng-i686/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=i686-unknown-linux-gnu \
        --prefix=/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-i686 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-i686/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-ppc64 AS elfutils-ppc64
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-ppc64 /opt/zlib-ng-ppc64/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=powerpc64-unknown-linux-gnu \
        --prefix=/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-ppc64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-ppc64/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-ppc64le AS elfutils-ppc64le
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-ppc64le /opt/zlib-ng-ppc64le/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=powerpc64le-unknown-linux-gnu \
        --prefix=/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-ppc64le \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-ppc64le/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-s390x AS elfutils-s390x
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-s390x /opt/zlib-ng-s390x/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=s390x-ibm-linux-gnu \
        --prefix=/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-s390x \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-s390x/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-x86_64 AS elfutils-x86_64
ARG elfutils_version
RUN apt-get update && apt-get install --no-install-recommends --yes \
        autopoint \
        pkg-config
COPY --from=zlib-ng-x86_64 /opt/zlib-ng-x86_64/ /
COPY --from=elfutils-base /usr/src/elfutils-${elfutils_version} /usr/src/elfutils
WORKDIR /usr/src/elfutils
RUN autoreconf -i
RUN CFLAGS=-fPIC ./configure \
        --disable-debuginfod \
        --disable-libdebuginfod \
        --host=x86_64-unknown-linux-gnu \
        --prefix=/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/elfutils-x86_64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install V=1
WORKDIR /opt/elfutils-x86_64/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr/lib
RUN rm *.so *.so.*

FROM crosstool-ng-base AS systemtap-base
ARG systemtap_version
RUN git clone \
        --branch=release-${systemtap_version} \
        --depth=1 \
        https://sourceware.org/git/systemtap.git \
        /usr/src/systemtap

FROM crosstool-ng-aarch64 AS systemtap-aarch64
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-aarch64 /opt/elfutils-aarch64/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-aarch64 /opt/zlib-ng-aarch64/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=aarch64-unknown-linux-gnu \
            --prefix=/usr/aarch64-unknown-linux-gnu/aarch64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-aarch64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-arm AS systemtap-arm
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-arm /opt/elfutils-arm/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-arm /opt/zlib-ng-arm/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=arm-unknown-linux-gnueabihf \
            --prefix=/usr/arm-unknown-linux-gnueabihf/arm-unknown-linux-gnueabihf/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-arm \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-i686 AS systemtap-i686
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-i686 /opt/elfutils-i686/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-i686 /opt/zlib-ng-i686/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=i686-unknown-linux-gnu \
            --prefix=/usr/i686-unknown-linux-gnu/i686-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-i686 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-ppc64 AS systemtap-ppc64
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-ppc64 /opt/elfutils-ppc64/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-ppc64 /opt/zlib-ng-ppc64/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=powerpc64-unknown-linux-gnu \
            --prefix=/usr/powerpc64-unknown-linux-gnu/powerpc64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-ppc64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-ppc64le AS systemtap-ppc64le
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-ppc64le /opt/elfutils-ppc64le/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-ppc64le /opt/zlib-ng-ppc64le/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=powerpc64le-unknown-linux-gnu \
            --prefix=/usr/powerpc64le-unknown-linux-gnu/powerpc64le-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-ppc64le \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-s390x AS systemtap-s390x
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-s390x /opt/elfutils-s390x/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-s390x /opt/zlib-ng-s390x/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=s390x-ibm-linux-gnu \
            --prefix=/usr/s390x-ibm-linux-gnu/s390x-ibm-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-s390x \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM crosstool-ng-x86_64 AS systemtap-x86_64
COPY --from=cp36-cp36m /opt/cp36-cp36m/ /opt/cp36-cp36m/
COPY --from=elfutils-x86_64 /opt/elfutils-x86_64/ /
COPY --from=systemtap-base /usr/src/systemtap /usr/src/systemtap
COPY --from=zlib-ng-x86_64 /opt/zlib-ng-x86_64/ /
WORKDIR /usr/src/systemtap
RUN PYTHON3=/opt/cp36-cp36m/bin/python3 \
        LIBS="-pthread -lz" \
        ./configure \
            --host=x86_64-unknown-linux-gnu \
            --prefix=/usr/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/sysroot/usr
RUN make \
        DESTDIR=/opt/systemtap-x86_64 \
        "-j$(getconf _NPROCESSORS_ONLN)" \
        install-oldincludeHEADERS

FROM base AS final-common
RUN apt-get update && apt-get install --no-install-recommends --yes \
        automake \
        ccache \
        cmake \
        git \
        make \
        ninja-build \
        patchelf \
        quilt

FROM final-common AS final-aarch64
COPY --from=crosstool-ng-aarch64 \
     /usr/aarch64-unknown-linux-gnu \
     /usr/aarch64-unknown-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/aarch64-unknown-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/aarch64-unknown-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/aarch64-unknown-linux-gnu-gcc
COPY --from=boost-aarch64 /opt/boost-aarch64/ /
COPY --from=capstone-aarch64 /opt/capstone-aarch64/ /
COPY --from=elfutils-aarch64 /opt/elfutils-aarch64/ /
COPY --from=systemtap-aarch64 /opt/systemtap-aarch64/ /
COPY --from=zlib-ng-aarch64 /opt/zlib-ng-aarch64/ /

FROM final-aarch64 AS final-aarch64-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp36-cp36m \
     /usr/aarch64-unknown-linux-gnu/cp36-cp36m

FROM final-aarch64 AS final-aarch64-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp37-cp37m \
     /usr/aarch64-unknown-linux-gnu/cp37-cp37m

FROM final-aarch64 AS final-aarch64-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp38-cp38 \
     /usr/aarch64-unknown-linux-gnu/cp38-cp38

FROM final-aarch64 AS final-aarch64-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp39-cp39 \
     /usr/aarch64-unknown-linux-gnu/cp39-cp39

FROM final-aarch64 AS final-aarch64-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp310-cp310 \
     /usr/aarch64-unknown-linux-gnu/cp310-cp310

FROM final-aarch64 AS final-aarch64-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp311-cp311 \
     /usr/aarch64-unknown-linux-gnu/cp311-cp311

FROM final-aarch64 AS final-aarch64-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp312-cp312 \
     /usr/aarch64-unknown-linux-gnu/cp312-cp312

FROM final-aarch64 AS final-aarch64-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-aarch64 \
     /usr/aarch64-unknown-linux-gnu/cp313-cp313 \
     /usr/aarch64-unknown-linux-gnu/cp313-cp313

FROM final-common AS final-arm
COPY --from=crosstool-ng-arm \
     /usr/arm-unknown-linux-gnueabihf \
     /usr/arm-unknown-linux-gnueabihf
ENV PATH=/usr/lib/ccache:/usr/arm-unknown-linux-gnueabihf/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/arm-unknown-linux-gnueabihf-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/arm-unknown-linux-gnueabihf-gcc
COPY --from=boost-arm /opt/boost-arm/ /
COPY --from=capstone-arm /opt/capstone-arm/ /
COPY --from=elfutils-arm /opt/elfutils-arm/ /
COPY --from=systemtap-arm /opt/systemtap-arm/ /
COPY --from=zlib-ng-arm /opt/zlib-ng-arm/ /

FROM final-arm AS final-arm-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-arm \
     /usr/arm-unknown-linux-gnueabihf/cp36-cp36m \
     /usr/arm-unknown-linux-gnueabihf/cp36-cp36m

FROM final-arm AS final-arm-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-arm \
     /usr/arm-unknown-linux-gnueabihf/cp37-cp37m \
     /usr/arm-unknown-linux-gnueabihf/cp37-cp37m

FROM final-arm AS final-arm-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-arm \
     /usr/arm-unknown-linux-gnueabihf/cp38-cp38 \
     /usr/arm-unknown-linux-gnueabihf/cp38-cp38

FROM final-arm AS final-arm-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-arm \
     /usr/arm-unknown-linux-gnueabihf/cp39-cp39 \
     /usr/arm-unknown-linux-gnueabihf/cp39-cp39

FROM final-arm AS final-arm-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-arm \
     /usr/arm-unknown-linux-gnueabihf/cp310-cp310 \
     /usr/arm-unknown-linux-gnueabihf/cp310-cp310

FROM final-arm AS final-arm-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-arm \
     /usr/arm-unknown-linux-gnueabihf/cp311-cp311 \
     /usr/arm-unknown-linux-gnueabihf/cp311-cp311

FROM final-arm AS final-arm-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-arm \
     /usr/arm-unknown-linux-gnueabihf/cp312-cp312 \
     /usr/arm-unknown-linux-gnueabihf/cp312-cp312

FROM final-arm AS final-arm-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-arm \
     /usr/arm-unknown-linux-gnueabihf/cp313-cp313 \
     /usr/arm-unknown-linux-gnueabihf/cp313-cp313

FROM final-common AS final-i686
COPY --from=crosstool-ng-i686 \
     /usr/i686-unknown-linux-gnu \
     /usr/i686-unknown-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/i686-unknown-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/i686-unknown-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/i686-unknown-linux-gnu-gcc
COPY --from=boost-i686 /opt/boost-i686/ /
COPY --from=capstone-i686 /opt/capstone-i686/ /
COPY --from=elfutils-i686 /opt/elfutils-i686/ /
COPY --from=systemtap-i686 /opt/systemtap-i686/ /
COPY --from=zlib-ng-i686 /opt/zlib-ng-i686/ /

FROM final-i686 AS final-i686-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-i686 \
     /usr/i686-unknown-linux-gnu/cp36-cp36m \
     /usr/i686-unknown-linux-gnu/cp36-cp36m

FROM final-i686 AS final-i686-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-i686 \
     /usr/i686-unknown-linux-gnu/cp37-cp37m \
     /usr/i686-unknown-linux-gnu/cp37-cp37m

FROM final-i686 AS final-i686-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-i686 \
     /usr/i686-unknown-linux-gnu/cp38-cp38 \
     /usr/i686-unknown-linux-gnu/cp38-cp38

FROM final-i686 AS final-i686-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-i686 \
     /usr/i686-unknown-linux-gnu/cp39-cp39 \
     /usr/i686-unknown-linux-gnu/cp39-cp39

FROM final-i686 AS final-i686-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-i686 \
     /usr/i686-unknown-linux-gnu/cp310-cp310 \
     /usr/i686-unknown-linux-gnu/cp310-cp310

FROM final-i686 AS final-i686-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-i686 \
     /usr/i686-unknown-linux-gnu/cp311-cp311 \
     /usr/i686-unknown-linux-gnu/cp311-cp311

FROM final-i686 AS final-i686-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-i686 \
     /usr/i686-unknown-linux-gnu/cp312-cp312 \
     /usr/i686-unknown-linux-gnu/cp312-cp312

FROM final-i686 AS final-i686-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-i686 \
     /usr/i686-unknown-linux-gnu/cp313-cp313 \
     /usr/i686-unknown-linux-gnu/cp313-cp313

FROM final-common AS final-ppc64
COPY --from=crosstool-ng-ppc64 \
     /usr/powerpc64-unknown-linux-gnu \
     /usr/powerpc64-unknown-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/powerpc64-unknown-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/powerpc64-unknown-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/powerpc64-unknown-linux-gnu-gcc
COPY --from=boost-ppc64 /opt/boost-ppc64/ /
COPY --from=capstone-ppc64 /opt/capstone-ppc64/ /
COPY --from=elfutils-ppc64 /opt/elfutils-ppc64/ /
COPY --from=systemtap-ppc64 /opt/systemtap-ppc64/ /
COPY --from=zlib-ng-ppc64 /opt/zlib-ng-ppc64/ /

FROM final-ppc64 AS final-ppc64-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp36-cp36m \
     /usr/powerpc64-unknown-linux-gnu/cp36-cp36m

FROM final-ppc64 AS final-ppc64-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp37-cp37m \
     /usr/powerpc64-unknown-linux-gnu/cp37-cp37m

FROM final-ppc64 AS final-ppc64-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp38-cp38 \
     /usr/powerpc64-unknown-linux-gnu/cp38-cp38

FROM final-ppc64 AS final-ppc64-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp39-cp39 \
     /usr/powerpc64-unknown-linux-gnu/cp39-cp39

FROM final-ppc64 AS final-ppc64-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp310-cp310 \
     /usr/powerpc64-unknown-linux-gnu/cp310-cp310

FROM final-ppc64 AS final-ppc64-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp311-cp311 \
     /usr/powerpc64-unknown-linux-gnu/cp311-cp311

FROM final-ppc64 AS final-ppc64-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp312-cp312 \
     /usr/powerpc64-unknown-linux-gnu/cp312-cp312

FROM final-ppc64 AS final-ppc64-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-ppc64 \
     /usr/powerpc64-unknown-linux-gnu/cp313-cp313 \
     /usr/powerpc64-unknown-linux-gnu/cp313-cp313

FROM final-common AS final-ppc64le
COPY --from=crosstool-ng-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu \
     /usr/powerpc64le-unknown-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/powerpc64le-unknown-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/powerpc64le-unknown-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/powerpc64le-unknown-linux-gnu-gcc
COPY --from=boost-ppc64le /opt/boost-ppc64le/ /
COPY --from=capstone-ppc64le /opt/capstone-ppc64le/ /
COPY --from=elfutils-ppc64le /opt/elfutils-ppc64le/ /
COPY --from=systemtap-ppc64le /opt/systemtap-ppc64le/ /
COPY --from=zlib-ng-ppc64le /opt/zlib-ng-ppc64le/ /

FROM final-ppc64le AS final-ppc64le-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp36-cp36m \
     /usr/powerpc64le-unknown-linux-gnu/cp36-cp36m

FROM final-ppc64le AS final-ppc64le-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp37-cp37m \
     /usr/powerpc64le-unknown-linux-gnu/cp37-cp37m

FROM final-ppc64le AS final-ppc64le-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp38-cp38 \
     /usr/powerpc64le-unknown-linux-gnu/cp38-cp38

FROM final-ppc64le AS final-ppc64le-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp39-cp39 \
     /usr/powerpc64le-unknown-linux-gnu/cp39-cp39

FROM final-ppc64le AS final-ppc64le-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp310-cp310 \
     /usr/powerpc64le-unknown-linux-gnu/cp310-cp310

FROM final-ppc64le AS final-ppc64le-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp311-cp311 \
     /usr/powerpc64le-unknown-linux-gnu/cp311-cp311

FROM final-ppc64le AS final-ppc64le-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp312-cp312 \
     /usr/powerpc64le-unknown-linux-gnu/cp312-cp312

FROM final-ppc64le AS final-ppc64le-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-ppc64le \
     /usr/powerpc64le-unknown-linux-gnu/cp313-cp313 \
     /usr/powerpc64le-unknown-linux-gnu/cp313-cp313

FROM final-common AS final-s390x
COPY --from=crosstool-ng-s390x \
     /usr/s390x-ibm-linux-gnu \
     /usr/s390x-ibm-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/s390x-ibm-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/s390x-ibm-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/s390x-ibm-linux-gnu-gcc
COPY --from=boost-s390x /opt/boost-s390x/ /
COPY --from=capstone-s390x /opt/capstone-s390x/ /
COPY --from=elfutils-s390x /opt/elfutils-s390x/ /
COPY --from=systemtap-s390x /opt/systemtap-s390x/ /
COPY --from=zlib-ng-s390x /opt/zlib-ng-s390x/ /

FROM final-s390x AS final-s390x-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-s390x \
     /usr/s390x-ibm-linux-gnu/cp36-cp36m \
     /usr/s390x-ibm-linux-gnu/cp36-cp36m

FROM final-s390x AS final-s390x-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-s390x \
     /usr/s390x-ibm-linux-gnu/cp37-cp37m \
     /usr/s390x-ibm-linux-gnu/cp37-cp37m

FROM final-s390x AS final-s390x-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-s390x \
     /usr/s390x-ibm-linux-gnu/cp38-cp38 \
     /usr/s390x-ibm-linux-gnu/cp38-cp38

FROM final-s390x AS final-s390x-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-s390x \
     /usr/s390x-ibm-linux-gnu/cp39-cp39 \
     /usr/s390x-ibm-linux-gnu/cp39-cp39

FROM final-s390x AS final-s390x-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-s390x \
     /usr/s390x-ibm-linux-gnu/cp310-cp310 \
     /usr/s390x-ibm-linux-gnu/cp310-cp310

FROM final-s390x AS final-s390x-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-s390x \
     /usr/s390x-ibm-linux-gnu/cp311-cp311 \
     /usr/s390x-ibm-linux-gnu/cp311-cp311

FROM final-s390x AS final-s390x-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-s390x \
     /usr/s390x-ibm-linux-gnu/cp312-cp312 \
     /usr/s390x-ibm-linux-gnu/cp312-cp312

FROM final-s390x AS final-s390x-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-s390x \
     /usr/s390x-ibm-linux-gnu/cp313-cp313 \
     /usr/s390x-ibm-linux-gnu/cp313-cp313

FROM final-common AS final-x86_64
COPY --from=crosstool-ng-x86_64 \
     /usr/x86_64-unknown-linux-gnu \
     /usr/x86_64-unknown-linux-gnu
ENV PATH=/usr/lib/ccache:/usr/x86_64-unknown-linux-gnu/bin:$PATH
RUN ln -s /usr/bin/ccache /usr/lib/ccache/x86_64-unknown-linux-gnu-g++
RUN ln -s /usr/bin/ccache /usr/lib/ccache/x86_64-unknown-linux-gnu-gcc
COPY --from=boost-x86_64 /opt/boost-x86_64/ /
COPY --from=capstone-x86_64 /opt/capstone-x86_64/ /
COPY --from=elfutils-x86_64 /opt/elfutils-x86_64/ /
COPY --from=systemtap-x86_64 /opt/systemtap-x86_64/ /
COPY --from=zlib-ng-x86_64 /opt/zlib-ng-x86_64/ /

FROM final-x86_64 AS final-x86_64-cp36-cp36m
COPY --from=cp36-cp36m /opt/cp36-cp36m /opt/cp36-cp36m
COPY --from=cp36-cp36m-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp36-cp36m \
     /usr/x86_64-unknown-linux-gnu/cp36-cp36m

FROM final-x86_64 AS final-x86_64-cp37-cp37m
COPY --from=cp37-cp37m /opt/cp37-cp37m /opt/cp37-cp37m
COPY --from=cp37-cp37m-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp37-cp37m \
     /usr/x86_64-unknown-linux-gnu/cp37-cp37m

FROM final-x86_64 AS final-x86_64-cp38-cp38
COPY --from=cp38-cp38 /opt/cp38-cp38 /opt/cp38-cp38
COPY --from=cp38-cp38-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp38-cp38 \
     /usr/x86_64-unknown-linux-gnu/cp38-cp38

FROM final-x86_64 AS final-x86_64-cp39-cp39
COPY --from=cp39-cp39 /opt/cp39-cp39 /opt/cp39-cp39
COPY --from=cp39-cp39-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp39-cp39 \
     /usr/x86_64-unknown-linux-gnu/cp39-cp39

FROM final-x86_64 AS final-x86_64-cp310-cp310
COPY --from=cp310-cp310 /opt/cp310-cp310 /opt/cp310-cp310
COPY --from=cp310-cp310-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp310-cp310 \
     /usr/x86_64-unknown-linux-gnu/cp310-cp310

FROM final-x86_64 AS final-x86_64-cp311-cp311
COPY --from=cp311-cp311 /opt/cp311-cp311 /opt/cp311-cp311
COPY --from=cp311-cp311-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp311-cp311 \
     /usr/x86_64-unknown-linux-gnu/cp311-cp311

FROM final-x86_64 AS final-x86_64-cp312-cp312
COPY --from=cp312-cp312 /opt/cp312-cp312 /opt/cp312-cp312
COPY --from=cp312-cp312-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp312-cp312 \
     /usr/x86_64-unknown-linux-gnu/cp312-cp312

FROM final-x86_64 AS final-x86_64-cp313-cp313
COPY --from=cp313-cp313 /opt/cp313-cp313 /opt/cp313-cp313
COPY --from=cp313-cp313-x86_64 \
     /usr/x86_64-unknown-linux-gnu/cp313-cp313 \
     /usr/x86_64-unknown-linux-gnu/cp313-cp313
