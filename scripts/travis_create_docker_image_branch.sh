#!/bin/bash

set -e

docker login -u $DOCKER_USER -p $DOCKER_PASS
export REPO=satosa/satosa
export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
docker build -f Dockerfile -t $REPO:$TAG .
docker push $REPO
