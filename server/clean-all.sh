#!/bin/bash
docker rm $(docker ps -aq)
docker system prune
docker volume prune
