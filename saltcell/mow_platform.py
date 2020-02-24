#!/usr/bin/env python3

"""
mow_platform.py

This is a module that should (in theory) provide all the logic to make a "best guess" to the
current platform and Return the data associated therein.
"""

#import salt
import logging
import requests
import urllib.parse

def plat_aws():
    """
    Guess If the Platform is AWS Related
    """

    logger = logging.getLogger("mow_platform.plat_aws")

    response_doc = {"belief" : False,
                    "belief_score" : 0,
                    "uri" : "unknown://::::unknown"}

    v2_tput_headers = {"X-aws-ec2-metadata-token-ttl-seconds" : "21600"}
    v2_tput_url = "http://169.254.169.254/latest/api/token"

    try:
        tput_request = requests.put(v2_tput_url, headers=v2_tput_headers)
        token = tput_request.text
    except Exception as v2_error:
        logger.info("I do not believe this is an AWS Host as I had an error accessing the API.")
        logger.debug("Error : {}".format(v2_error))
        response_doc["belief_reson"] = "Error with API Request"
    else:
        if tput_request.status_code == requests.codes.ok:
            # Let's Get My Data
            try:
                v2_tget_headers = {"X-aws-ec2-metadata-token": token}
                v2_tget_url = "http://169.254.169.254/latest/dynamic/instance-identity/document"

                tput_dyn_doc = requests.get(v2_tget_url, headers=v2_tget_headers).json()
            except Exception as tget_error:
                logger.error("Either v2 API is turned off or this might not be AWS.")
                response_doc["belife_reason"] = "No Dynmic Doc Available from API"
            else:
                response_doc["belief_score"] = 0.8
                response_doc["data"] = dict()

                # Time to Guess if Service is ec2
                service = "ec2"

                with open("/sys/hypervisor/uuid", "r") as hypervisor_uuid_file:
                    hypervisor_uuid = hypervisor_uuid_file.read()

                    if hypervisor_uuid.startswith("ec2"):
                        response_doc["belief_score"] = True
                        response_doc["belief_score"] = 1.0
                        service = "ec2"
                    else:
                        service = hypervisor_uuid[0:3]

                    response_doc["data"]["aws_service_guess"] = service
                    response_doc["data"]["aws_hypervisor_uuid"] = hypervisor_uuid

                for k, v in tput_dyn_doc.items():
                    # Place My Known Data Here
                    response_doc["data"]["aws_{}".format(k)] = v

                # Guess ARN
                response_doc["data"]["arn"] = "arn:{aws_service_guess}:{aws_region}:{aws_accountId}:instance/{aws_instanceId}".format(response_doc["data"])
                response_doc["data"]["arn_args"] = {**tput_dyn_doc}
                response_doc["data"]["arn_args_encoded"] = urllib.parse.urlencode(tput_dyn_doc)
                response_doc["uri"] = "arn://{aws_service_guess}:{aws_region}:{aws_accountId}:instance/{aws_instanceId}?{arn_args_encoded}".format(response_doc["data"])

        else:
            response_doc["belief_reason"] = "Bad API Response"

    return response_doc

def guess(*upstream_opts, **upstream_kwargs):

    """
    This is the main entry point. From here the system will call all the neccessary things
    to "Best Guess" the platform that this box is running on.
    """

    logger = logging.getLogger("mow_platform.guess")

    _plat_guess = {"AWS": {"function" : plat_aws,
                           "description" : "Amazon Web Services"}}

    best_guess = dict(current_guess="unknown", belief_score=0, uri="unknown://::::unknown")

    for guess, details in _plat_guess.items():

        logger.info("Checking Platform {}".format(guess))
        logger.debug("Platform {} : {}".format(guess, details.get("description", "No Description")))

        this_guess = details["function"]()

        if this_guess["belief"] is True:
            # Belief is Solid moving forward with this information
            logger.debug("Solid belife in Platform {}".format(guess))
            best_guess = this_guess
            break
        elif this_guess["belief_score"] > 0 and this_guess["belief_score"] > best_guess["belief_score"]:
            logger.debug("This is my Best Guess so far with a Score of {}".format(this_guess["belief_score"]))
            best_guess = this_guess
            # Now check the rest of the items.

    guess_data = {**this_guess.get("data", dict()), "uri" : this_guess["uri"], "ip_intel" : this_guess.get("ip_intel", list())}

    return guess_data


