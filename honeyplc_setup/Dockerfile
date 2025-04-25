# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Set working directory
WORKDIR /honeyplc

# Install dependencies
RUN apt-get update && apt-get install -y \
	python3 \
	python3-pip \
	git \
	build-essential \
	libpcap-dev \
	nmap \
	snmp \
	wget \
	&& rm -rf /var/lib/apt/lists/*

# Install Snap7
RUN git clone https://github.com/scada-tools/snap7.git /tmp/snap7 \
	&& cd /tmp/snap7/build/unix \
	&& make -f unix_Makefile.mk all \
	&& cp /tmp/snap7/build/bin/x86_64-linux/libsnap7.so /usr/lib/ \
	&& ldconfig \
	&& rm -rf /tmp/snap7

# Install Honeyd
RUN git clone https://github.com/provos/honeyd.git /tmp/honeyd \
	&& cd /tmp/honeyd \
	&& ./configure \
	&& make \
	&& make install \
	&& rm -rf /tmp/honeyd

# Copy HoneyPLC source code
COPY . /honeyplc

# Install Python dependencies (if any)
RUN pip3 install python-nmap

# Expose common PLC ports (e.g., S7comm, HTTP, SNMP)
EXPOSE 102 80 161/udp

CMD ["/bin/bash"]
