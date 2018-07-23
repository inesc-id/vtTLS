for i in {0..50}
do
  echo 'Test' $i 'of 50'
  ./client 172.17.39.6 test10m.txt >> result10m.txt;
  sleep 2;
done
