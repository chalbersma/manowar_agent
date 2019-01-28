#!/usr/bin/env python3

import setuptools
import sys
import os
import git

current_repo = git.Repo()

if current_repo.bare:
    print("Something went wrong Repo is Bare, Failing the Build.")
    sys.exit(1)
else:

    env_keys = dict(os.environ).keys()

    travis_keys = [ key for key in env_keys if key.startswith("TRAVIS") ]

    for key in travis_keys:
        print("{} : {}".format(key, os.environ[key]))

    travis_repo = os.environ.get("TRAVIS_REPO_SLUG", "NOTRAVIS")
    travis_pull_req = os.environ.get("TRAVIS_PULL_REQUEST", "UNKNOWN")
    travis_branch = os.environ.get("TRAVIS_BRANCH", "UNKNOWN")
    travis_event_type = os.environ.get("TRAVIS_EVENT_TYPE", "UNKNOWN")
    travis_tag = os.environ.get("TRAVIS_TAG", False)

# Set Default Version
version = "0.0.0"
upload_to_pypi = False

# My Known Good Repository
if travis_repo == "chalbersma/manowar_agent" and travis_branch == "master" and travis_tag is not False:
    # Make a Version Fix here that equls the tag
    print("We're working with a Tag.")
    print(travis_tag)
    pass


with open("README.md", "r") as fh:
    long_description = fh.read()

# Get Version

setuptools.setup(
    name="stingcell",
    version="0.0.0",
    author="Chris Halbersma",
    author_email="chris+manowar@halbersma.us",
    description="Package to Add as a Collector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chalbersma/manowar",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent"
    ],
    install_requires=[
        "Jinja2",
        "jq",
        "PyYAML",
        "requests",
        "salt"
    ],
    scripts=["manowar_saltcell"]
)
