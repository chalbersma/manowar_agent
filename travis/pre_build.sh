#!/bin/bash

mkdir docs

# Var Debug Findings
echo -e "TRAVIS_PULL_REQUEST_BRANCH : ${TRAVIS_PULL_REQUEST_BRANCH}"
echo -e "TRAVIS_PULL_REQUEST_SLUG : ${TRAVIS_PULL_REQUEST_SLUG}"
echo -e "TRAVIS_REPO_SLUG : ${TRAVIS_REPO_SLUG}"
echo -e "TRAVIS_BRANCH : ${TRAVIS_BRANCH}"
echo -e "TRAVIS_EVENT_TYPE : ${TRAVIS_EVENT_TYPE}"
echo -e "Git Branch : $(git rev-parse --abbrev-ref HEAD)"

echo -e "Python Verison : "
python3 -V
python -V
