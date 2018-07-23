# MultiTLS command line interface

One Paragraph of project description goes here

## Getting Started

Secure channel with cipher diversity

### Prerequisites

Docker

### Installing


```
$ docker build -t multitls .
```


## Run the examples

Add additional notes about how to deploy this on a live system

Start two new containers from the previous built image: one for the server and another for the client:

```
$ docker create -i multitls --name multitls-client
$ docker create -i multitls --name multitls-server
```

Then, start each container in a different terminal:

```
$ docker start -a -i multitls-client
```

```
$ docker start -a -i multitls-client
```


### MultiTLS usage

#### VM-Server

```
$ multiTLS -s <port-number> <number-of-tunnels> <cert-1> <cafile-1> <cert-2> <cafile-2>
```

#### VM-Client

```
$ multiTLS -c <port-number> <number-of-tunnels> <IPServer> <cert-1> <cafile-1> <cert-2> <cafile-2>
```



### MultiTLS simpe execution example

In the server container with an IP address **192.169.1.1** execute: 

```
$ multiTLS -s 11444 2 cert-1.pem cafile-1.crt cert-2.pem cafile-2.ctr
```

In the client container execute:

```
$ multiTLS -c 11444 2 192.169.1.1 cert-1.pem cafile-1.crt cert-2.pem cafile-2.ctr
```

### Example of an ECHO Application

In the server container with an IP address **192.169.1.1** execute: 

```
$ socat - tcp-listen:11445
```

In the client container execute:

```
$ socat tcp:192.169.1.1:11445 echo
```



## Built With

* [OpenSSL](https://www.openssl.org) - The full-featured toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols
* [Socat](http://www.dest-unreach.org/socat/doc/socat.html) - Multipurpose relay (SOcket CAT)

## Authors

* **[Ricardo Moura](https://github.com/R3Moura)** - *Development of the protocol*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* **[Prof. Miguel Correia](https://github.com/mpcorreia)** 
* **[Prof. Miguel Pardal](https://github.com/miguelpardal)** 
* **[David Matos](https://github.com/davidmatos)**


