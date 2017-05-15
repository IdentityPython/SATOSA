#!/bin/bash

set -e

# Travis does not know which branch the repo is on when building a tag
# Make sure to only call this script when building tags

docker login -u $DOCKER_USER -p $DOCKER_PASS
export REPO=satosa/satosa
export TAG=latest
docker build -f Dockerfile -t $REPO:$TAG .
if [ -n "$TRAVIS_TAG" ]; then
  docker tag $REPO:$TAG $REPO:$TRAVIS_TAG
fi
docker push $REPO
