FROM centos:7

ADD . /tmp
WORKDIR /tmp
RUN ./build.sh
