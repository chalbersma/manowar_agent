#!/usr/bin/env python3

'''
An attempt to make a ghetto packaging script.
'''

import setuptools
import sys
import os
import git
import subprocess # nosec

current_repo = git.Repo()

if current_repo.bare:
    print("Something went wrong Repo is Bare, Failing the Build.")
    sys.exit(1)
else:

    env_keys = dict(os.environ).keys()

    travis_keys = [key for key in env_keys if key.startswith("TRAVIS")]

    for key in travis_keys:
        print("{} : {}".format(key, os.environ[key]))

    travis_repo = os.environ.get("TRAVIS_REPO_SLUG", "NOTRAVIS")
    travis_pull_req = os.environ.get("TRAVIS_PULL_REQUEST", "UNKNOWN")
    travis_branch = os.environ.get("TRAVIS_BRANCH", "UNKNOWN")
    travis_event_type = os.environ.get("TRAVIS_EVENT_TYPE", "UNKNOWN")
    travis_tag = os.environ.get("TRAVIS_TAG", "")
    travis_build_no = os.environ.get("TRAVIS_BUILD_NUMBER", 0)

    print(travis_build_no)

# Set Default Version
version = "0.0.0"
upload_to_pypi = False

# My Known Good Repository
if travis_repo == "chalbersma/manowar_agent" and travis_branch == "master" and len(travis_tag) > 0:
    # Make a Version Fix here that equls the tag
    print("Tagged Branch : {}".format(travis_tag))
    version = travis_tag
    upload_to_pypi = "prod"
elif travis_repo == "chalbersma/manowar_agent":
    # This is in my repo and
    version = "0.0.{}".format(travis_build_no)
    print("VERSION : {}".format(version))
    upload_to_pypi = "stag"
else:
    upload_to_pypi = False

if upload_to_pypi is not False and upload_to_pypi == "stag":
    os.environ["TWINE_USERNAME"] = os.environ.get("PYPI_STAG_UNAME", "whoidit")
    os.environ["TWINE_PASSWORD"] = os.environ.get("PYPI_STAG_PASSWD", "whasit")
    twine_cmd = ["twine", "upload", "--repository-url", "https://test.pypi.org/legacy/", "dist/*"]
elif upload_to_pypi is not False and upload_to_pypi == "stag":
    os.environ["TWINE_USERNAME"] = os.environ.get("PYPI_PROD_UNAME", "whoidit")
    os.environ["TWINE_PASSWORD"] = os.environ.get("PYPI_PROD_PASSWD", "whasit")
    twine_cmd = ["twine", "upload", "dist/*"]
else:
    # Not Uploading
    pass


print("VERSION : {}".format(version))

with open("README.md", "r") as fh:
    long_description = fh.read()

# Get Version

setuptools.setup(
    name="manowar_agent",
    version=version,
    author="Chris Halbersma",
    author_email="chris+manowar@halbersma.us",
    description="Package to Add as a Collector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chalbersma/manowar",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Topic :: Security"
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

if upload_to_pypi is not False:

    print("Attempting to Upload to PyPi : {}".format(upload_to_pypi))

    result = subprocess.check_call(twine_cmd) # nosec

    print("Result : {}".format(result))
else:
    print("Not attempting to Upload.")
