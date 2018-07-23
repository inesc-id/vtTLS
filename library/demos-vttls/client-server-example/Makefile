all: client server

client: client.cpp
	g++ -o client -g client.cpp read_line.c demo.c -L/usr/local/vttls/lib -lssl -lcrypto -ldl
	
server: server.cpp
	g++ -o server -g server.cpp read_line.c -L/usr/local/vttls/lib -lssl -lcrypto -ldl

clean:
	rm -f *.o client server
