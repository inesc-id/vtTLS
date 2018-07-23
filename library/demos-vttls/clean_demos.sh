# Bash script to clean all the demos before
# commiting to git

echo 'Entering client-server-example...'
cd client-server-example
make clean

echo 'Entering client-server-openssl-example...'
cd ../client-server-openssl-example
make clean

echo 'Entering client-server-send-message...'
cd ../client-server-send-message
make clean

echo 'Finished!'