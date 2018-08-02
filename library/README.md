# vtTLS - Library

VTTLS is a diverse and redundant vulnerability-tolerant communication protocol. There are often con- cerns about the strength of some of the encryption mechanisms used in SSL/TLS channels, with some regarded as insecure at some point in time. These mechanisms play a massive role in network se- curity, including cloud computing and infrastructures. VTTLS is our solution to mitigate the problem of secure communication channels being vulnerable to attacks due to unexpected vulnerabilities in its mechanisms. It is based on diversity and redundancy of cryptographic mechanisms and certificates to ensure a secure communication even when one or more mechanisms are vulnerable. VTTLS relies on a combination of k cipher suites which ensure that even if `k − 1` cipher suites are insecure or vulnerable, the communication channel remains secure due to the remaining secure cipher suite. We evaluated the performance and cost of VTTLS by comparing it to a recent TLS implementation, OpenSSL.

## Running an example application using Docker

This document describes the steps to install a container (lightweight virtual machine) with the VT-TLS (Vulnerability Tolerant Transport Layer Security) protocol implementation which will enable a vulnerability-tolerant channel test between two peers. We use Docker to create a virtual machine with the code and the examples.



### Prerequisites

You need Docker to run this example

### Instructions

To create a Docker container with vtTLS, execute the following command from within the VT-TLS folder:

```
docker build -t vttls .

docker create -t -i vttls
docker start -a -i <containerId>
```


The first command will create an image with the tag vttls. It can take several minutes to complete.

The second command creates a container from the image. The command outputs the created container identifier. Something like: `f24cfb66ba19523ce9e3ce535312085451fb194407d87058ddfd3b7fdda9cb12`

The third command starts the container. The identifier printed to the console by the previous command must be provided as argument. The container starts in interactive mode, meaning that the console is now executing commands inside the container.
Running the example
vtTLS comes with several examples. To run the examples go the the demos folder:

```
cd /data/vtTLS/demos-supertls
```


In this guide we will execute the example client-server-send-message. This example allows to send one message (given as parameter) from the client to the server using the vtTLS protocol.

First, navigate to the demo folder by executing:

```
cd /data/vtTLS/demos-supertls/client-server-send-message/
```


Then, start the server:

```
./server &
```

Finally execute the client:

```
./client 127.0.0.1 Hello
```
The first argument is the server address (localhost in this case) and the second argument is the message to send. The server prints diagnostic messages like the following:

```
Connection from 100007f, port 10c9
SSL connection using ECDH-ECDSA-AES256-GCM-SHA384
SSL connection using AES128-SHA256
The SuperTLS Handshake took 1 ms
SSL connection using ECDH-ECDSA-AES256-GCM-SHA384
SSL connection using AES128-SHA256
Server certificate:
         subject: /C=PT/ST=LISBON/L=RNL/O=INESC/OU=INESC/CN=ECDHE/emailAddress=ECDHE@ist
         issuer: /C=PT/ST=LISBON/L=RNL/O=INESC/OU=INESC/CN=ECDHE/emailAddress=ECDHE@ist
Server second certificate:
         subject: /C=PT/ST=Lisbon/L=Lisbon/O=IST/OU=Computer Science/CN=AMJ/emailAddress=andrej@hotmail.com
         issuer: /C=PT/ST=Lisbon/L=Lisbon/O=IST/OU=Computer Science/CN=AMJ/emailAddress=andrej@hotmail.com
Got 5 chars:'Hello'
total_size: 5
-- total_size: 5
[1]+  Done                    ./server
```


Notice that two diverse cipher suites are being used. And also two different server certificates. By using two diverse ciphers, if a vulnerability is found in one of them, the other can still provide protection. In other words, vtTLS can tolerate one vulnerability.
Running the example with 2 containers
We will now run the same demo, but with two containers: one for the client, one for the receiver. We will use a single line that combines create and start.

Open one terminal and create the server container:

```
docker start -a -i $(docker create -t -i vttls)
```

Open another terminal and create the client container (using the same image):

```
docker start -a -i $(docker create -t -i vttls)
```




On the server container execute the following command to get the <IP Address> value:

```
hostname -I
```

Then run:

```
cd /data/vtTLS/demos-supertls/client-server-send-message
./server
```

In the client container, run the following using the server container IP address:

```
cd /data/vtTLS/demos-supertls/client-server-send-message
./client <server container IP address> Hello
```

Both containers will output a result similar to the following:

```
The SuperTLS Handshake took 2 ms
SSL connection using ECDH-ECDSA-AES256-GCM-SHA384
SSL connection using AES128-SHA256
Server certificate:
	 subject: /C=PT/ST=LISBON/L=RNL/O=INESC/OU=INESC/CN=ECDHE/emailAddress=ECDHE@ist
	 issuer: /C=PT/ST=LISBON/L=RNL/O=INESC/OU=INESC/CN=ECDHE/emailAddress=ECDHE@ist
Server second certificate:
	 subject: /C=PT/ST=Lisbon/L=Lisbon/O=IST/OU=Computer Science/CN=AMJ/emailAddress=andrej@hotmail.com
	 issuer: /C=PT/ST=Lisbon/L=Lisbon/O=IST/OU=Computer Science/CN=AMJ/emailAddress=andrej@hotmail.com
-- total_size: 5

```

This concludes the vtTLS demonstration using Docker containers.



## Built With

* [Docker](http://docker.com/)
* [OpenSSL](https://www.openssl.org/)

## Authors

* **André Joaquim** - *Development of the library* - [GitHub](https://github.com/AndreJoaquim)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* [**David Matos**](https://github.com/davidmatos)
* [**Prof. Miguel Pardal**](https://github.com/miguelpardal)
* [**Prof. Miguel Correia**](https://github.com/mpcorreia)
