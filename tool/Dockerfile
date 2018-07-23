FROM ubuntu:18.04

RUN apt-get update

RUN apt-get install -y build-essential

RUN apt-get install -y wget

RUN wget https://www.openssl.org/source/old/1.1.0/openssl-1.1.0g.tar.gz 

RUN tar -zxvf openssl-1.1.0g.tar.gz 

RUN cd openssl-1.1.0g && \
    ./config && \
    make && \ 
    make clean && \
    make install

RUN wget http://www.dest-unreach.org/socat/download/socat-1.7.3.2.tar.gz 

RUN tar -zxvf socat-1.7.3.2.tar.gz 

RUN cd socat-1.7.3.2 && \
    ./configure && \
    make && \
    make install

COPY source/multiTLS /bin/

RUN chmod +x /bin/multiTLS 

