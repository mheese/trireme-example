FROM ubuntu
MAINTAINER Bernard Van De Walle <bernard@aporeto.com>

RUN mkdir -p /opt/trireme
RUN apt-get update && apt-get install -y \
    libnetfilter-queue1 \
    iptables \
    iproute2 \
    ipset

ADD trireme-example /opt/trireme/trireme-example

ENTRYPOINT ["/opt/trireme/trireme-example"]
