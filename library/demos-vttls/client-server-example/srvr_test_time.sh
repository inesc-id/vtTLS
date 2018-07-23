for i in {1..50}
do
  echo 'Launching server' $i 'on port 1111';
  ./server 1111 >> result.txt;
  sleep 2;
done