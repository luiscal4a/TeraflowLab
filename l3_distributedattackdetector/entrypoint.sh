cd /
echo "Launching TSTAT service"
./tstat -l -i $INTERFACE -s piped >> /dev/null &
TSTAT_PID=`echo $!`
# Wait for tstat to create the necessary directories
echo "Waiting for tstat to generate the directories"
date=$(date +'%Y_%m_%d_%H_%M')
sleep 5
TSTAT_PATH="/piped/$date.out"
echo "Starting STA"

cd /
python3 .
echo "All the process are running"
cd /
