docker network create -d bridge teraflowbridge

sudo docker run -d --name=am -p 10002:10002 --network=teraflowbridge l3_attackmitigator .
sudo docker run -d --name=cad -p 10001:10001 --network=teraflowbridge l3_centralizedattackdetector .
sudo docker run -d --name=dad -p 10000:10000 --network=host l3_distributedattackdetector .
