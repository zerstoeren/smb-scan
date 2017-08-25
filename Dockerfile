#FROM ubuntu:14.04
From ubuntu:14.04

#########################################################
# Environment
#########################################################

CMD ["/bin/bash"]

#########################################################
# Update and install pre-requisites
#########################################################

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get update && apt-get install -y \
    python-smbc \
    python-pip

#########################################################
# install smb-scan and pip install netaddr
#########################################################

RUN git clone https://github.com/zerstoeren/smb-scan
RUN pip install -r smb-scan/requirements.txt
RUN mv smb-scan /root/

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
