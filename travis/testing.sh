#!/bin/bash

# Bandit Checks

# Encoding Check

################### Python Checks #####################################
# ./jelly_api & ./jelly_display are the older versions of
# this project. They do not and should evaluated and are
# there only in case something needs to be turned back on.
python_files=$(find . -type f -regex ".*\.py$")

for file in ${python_files} ; do
  this_temp=$(mktemp /tmp/banditout.XXXXX)
  bandit "${file}" > "${this_temp}"
  this_file_good=$?
  if [[ ${this_file_good} -gt 0 ]] ; then
    echo -e "BANDIT: ${file} had issues please investigate."
    cat "${this_temp}"
    exit 1
  else
    echo -e "BANDIT: ${file} good."
  fi

  # Get bandit working first

  pylint ${file}
  if [[ $? -gt 0 ]] ; then
    echo -e "PYLINT:: ${file} had issues please investigate."
  fi

done


################# Run Manowar in this Version to test ###################
./manowar_agent -v -c etc/manowar_agent/saltcell.yaml --print
