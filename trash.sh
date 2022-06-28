docker rmi $(docker images -f "dangling=true" -q)
docker network prune -f
