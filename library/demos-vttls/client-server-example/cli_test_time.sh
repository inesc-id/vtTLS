for i in {1..50}
do
  echo 'Test' $i ' of 50';
  echo './client 172.17.39.2' $i 'test1g.txt >> 1g_result.txt';
  ./client 172.17.39.2 1111 test1g.txt >> 1g_result.txt;
  sleep 2;
done
