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
    current_branch = current_repo.active_branch.name
    travis_repo = os.environ.get("TRAVIS_REPO_SLUG", "NOTRAVIS")
    travis_branch = os.environ.get("TRAVIS_BRANCH", "UNKNOWN")
    travis_event_type = os.environ.get("TRAVIS_EVENT_TYPE", "UNKNOWN")

    print(current_branch, travis_repo, travis_branch, travis_event_branch)
    sys.exit(0)



with open("README.md", "r") as fh:
    long_description = fh.read()

# Get Version

setuptools.setup(
    name="stingcell",
    version=,
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
