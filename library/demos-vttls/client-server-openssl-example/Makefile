all: client server

client: cli.cpp
	g++ -o client -g cli.cpp -L/usr/include/openssl -lssl -lcrypto -ldl
	
server: serv.cpp
	g++ -o server -g serv.cpp -L/usr/include/openssl -lssl -lcrypto -ldl

clean:
	rm -f *.o client server
