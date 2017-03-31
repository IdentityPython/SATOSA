#!/bin/bash

set -e

docker login -u $DOCKER_USER -p $DOCKER_PASS
export REPO=satosa/satosa
export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $TRAVIS_BRANCH ; fi`
docker build -f Dockerfile -t $REPO:$TAG .
if [ -n "$TRAVIS_TAG" ]; then
  docker tag $REPO:$TAG $REPO:$TRAVIS_TAG
fi
docker push $REPO
