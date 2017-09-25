FROM ubuntu
MAINTAINER Bernard Van De Walle <bernard@aporeto.com>

RUN mkdir -p /opt/trireme/trireme-example
RUN apt-get update && apt-get install -y \
    libnetfilter-queue1 \
    iptables \
    iproute2 \
    ipset
RUN chmod +x ./opt/trireme/trireme-example

ADD . /opt/trireme/trireme-example

WORKDIR /opt/trireme/trireme-example
