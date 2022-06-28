echo "BUILD Attack Mitigator"
docker build -t l3_attackmitigator -f ./l3_attackmitigator/dockerfile ./l3_attackmitigator

echo "BUILD Centralized Attack Detector"
docker build -t l3_centralizedattackdetector -f ./l3_centralizedattackdetector/service/dockerfile ./l3_centralizedattackdetector/service

echo "BUILD Distributed Attack Detector"
docker build -t l3_distributedattackdetector -f ./l3_distributedattackdetector/dockerfile ./l3_distributedattackdetector
