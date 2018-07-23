all: client server

client: client.cpp
	g++ -o client -g client.cpp -L/usr/local/vttls/lib -lssl -lcrypto -ldl
	
server: server.cpp
	g++ -o server -g server.cpp -L/usr/local/vttls/lib -lssl -lcrypto -ldl

clean:
	rm -f *.o client server
