#!/usr/bin/env python3

'''
A ClientSide Collector
'''

import socket
import time
import json
import ipaddress
import logging
import os
import sys
import urllib

import yaml
import requests
import pyjq
# For AWS Service Detection
import ec2_metadata

import saltcell.mown

class Host:

    '''
    Collects Data Describing the Local Host using the configs specified.
    '''

    def __init__(self, minion_file="minion", base_config_file=False, local_cols=[False, None],
                 host_configs=False, ipintel_configs=False,
                 noupload=False, sapi_configs=False):

        self.logger = logging.getLogger("saltcell.clientcollector.Host")

        self.noupload_runtime = noupload

        self.minion_file = minion_file

        self.salt_caller = self.start_minion()

        self.base_config_file = self.get_configs(base_config_file, local_cols)

        self.host_configs = host_configs

        self.ec2_data = self.get_aws_ec2_data(get_collections=True)

        self.mown = self.gethostmeta()

        self.collection_info = self.getall_collections()

        # Service Specific Extends Here
        if self.ec2_data["is_ec2"] is True:
            self.collection_info["aws_info"] = self.ec2_data["aws_info"]

            # Add IP Data
            self.collection_info["ipv4_addr"] = {**self.collection_info["ipv4_addr"], **self.ec2_data["aws_ipv4"]}
            self.collection_info["ipv6_addr"] = {**self.collection_info["ipv6_addr"], **self.ec2_data["aws_ipv6"]}

        # elif self.next_platform is true for the future

        self.basedata = self.getbasedata()

        self.ipintel_configs = ipintel_configs

        self.sapi_configs = sapi_configs

        if self.ipintel_configs.get("dointel", False) is True:
            self.logger.debug("Collecting IP Intel.")
            self.myipintel = self.ipintel()
        else:
            # Empty
            self.logger.warning("Not attempting to collect IP Intel.")
            self.myipintel = list()

        # Now Try to Upload
        self.eval_upload()

    def todict(self):

        '''
        Returns Dictionary of my Data
        '''

        return_dict = {"collection_data" : self.collection_info,
                       "ip_intel" : self.myipintel,
                       **self.basedata}

        return return_dict

    def eval_upload(self):

        '''
        Evaluates and does the endpoint stuff
        '''

        response_code = False

        if self.noupload_runtime:
            self.logger.warning("Not uploading as noupload option specified at runtime, ignoring confiuration.")
        elif isinstance(self.sapi_configs, dict) and self.sapi_configs.get("sapi_do_api", False) is False:
            self.logger.warning("Not Uploading as sapi_do_api turned off in configs.")
        elif "sapi_endpoint" not in self.sapi_configs.keys():
            self.logger.error("Not Uploading as sapi_endpoint not set.")
        else:
            # It's Turned on
            post_data = self.todict()

            for this_endpoint in self.sapi_configs["sapi_endpoints"]:

                url = this_endpoint.get("url", False)
                name = this_endpoint.get("name", url)

                headers = dict()

                if "sapi_token" in this_endpoint.keys() and "sapi_username" in this_endpoint.keys():
                    headers["Authorization"] = "{}:{}".format(str(this_endpoint["sapi_username"]), this_endpoint["sapi_token"])
                else:
                    self.logger.warning("sapi_username and/or sapi_token not set in config. No Auth added (normally).")

                headers.update(this_endpoint.get("custom_headers", {}))

                query_args = dict()
                query_args.update(this_endpoint.get("custom_query_args", {}))

                try:
                    post_request = requests.post(url, data=post_data, headers=headers, params=query_args)
                except Exception as upload_exception:
                    self.logger.error("Unable to Upload to endpoint : {} with error : {}".format(name, str(upload_exception)))
                else:
                    response_code = post_request.status_code
                    if response_code == 200:
                        self.logger.info("Data Successfully Posted to : {}".format(name))
                    else:
                        self.logger.warning("Data posted to : {} but returned status code {} ".format(name, response_code))

        return response_code



    def get_configs(self, base_config_file, local_cols):

        '''
        Ensure I have my configs. Optionally read the config file
        from disk if I've been given a string

        Read Local Collections from Disk.
        '''

        if isinstance(base_config_file, dict):
            # I've been given the configuration
            to_collect_items = base_config_file
        elif isinstance(base_config_file, str):
            # I've been given a filename parse it
            with open(base_config_file, "r") as base_config_file_obj:
                try:
                    to_collect_items = yaml.safe_load(base_config_file_obj)
                except yaml.YAMLError as yaml_error:
                    self.logger.error("Unable to read collection configuration file {} with error : \n{}".format(base_config_file, str(yaml_error)))
                    to_collect_items = dict()

        if local_cols[0] is True:
            # Do Local Cols
            collection_d_dir = local_cols[1]
            collections_files = list()
            for (dirpath, dirnames, filenames) in os.walk(collection_d_dir):
                if len(dirnames) > 0:
                    self.logger.debug("Ignoring Subdirectories : {}".format(dirnames))
                for singlefile in filenames:
                    onefile = dirpath + "/" +  singlefile
                    #print(singlefile.find(".ini", -4))
                    if singlefile.find(".yaml", -4) > 0:
                        # File ends with .ini Last 4 chars
                        collections_files.append(onefile)

            for collection_file in collections_files:
                try:
                    # Read Our INI with our data collection rules
                    this_local_coll = yaml.safe_load(collection_file)
                except Exception as e: # pylint: disable=broad-except, invalid-name
                    sys.stderr.write("Bad collection configuration file {} cannot parse: {}".format(collection_file, str(e)))
                else:
                    # I've read and parsed this file let's add the things
                    for this_new_coll_key in this_local_coll.get("collections", {}).keys():
                        to_collect_items["collections"][this_new_coll_key] = this_local_coll[this_new_coll_key]

        return to_collect_items

    def start_minion(self):

        '''
        Starting up a Minion. Generally I'm starting up a Self contained minion
        But a fully configured one can be used here if the correct minion config
        file is specified in the configuration.
        '''

        # Any Earlier and I'll fubar the logger
        import salt.config
        import salt.client

        minion_opts = salt.config.minion_config(self.minion_file)

        salt_caller = salt.client.Caller(c_path=".", mopts=minion_opts)

        return salt_caller


    def getone(self, cname, collection):

        '''
        Logic to Collect one thing from the host

        Does the logic to use salt_caller to grab the data.
        '''

        results_dictionary = dict()
        results_dictionary[cname] = dict()

        is_multi = collection.get("multi", False)
        len_zero_default = collection.get("len_zero_default", None)

        if collection.get("salt", False) is True:

            try:
                this_find = self.salt_caller.function(collection["saltfactor"], \
                                                      *collection.get("saltargs", list()), \
                                                      **collection.get("saltkwargs", dict()))
            except Exception as salt_call_error:
                self.logger.error("Unable to Run Salt Command for {}".format(cname))
                results_dictionary[cname]["default"] = "error"
                results_dictionary[cname]["salt_error"] = "{}".format(salt_call_error)
            else:

                self.logger.debug("Results for {} : \n{}".format(cname, json.dumps(this_find, default=str)))

                if is_multi:
                    # Multi so do the JQ bits
                    try:
                        #parsed_result = jq.jq(collection["jq_parse"]).transform(this_find)
                        parsed_result = pyjq.first(collection["jq_parse"], this_find)
                    except Exception as JQ_Error:
                        self.logger.debug("When parsing {} Found results but JQ Parsing Failed.".format(JQ_Error))
                        results_dictionary[cname] = {"jq_error" : str(JQ_Error),
                                                     "jq_pre_found" : str(this_find)[:100]}
                    else:
                        if parsed_result is None:
                            # No Results
                            results_dictionary[cname] = {"none":"none"}

                            if len_zero_default is not None and isinstance(len_zero_default, dict):
                                results_dictionary[cname] = len_zero_default
                            elif len_zero_default is not None and isinstance(len_zero_default, str):
                                results_dictionary[cname] = {"default" : len_zero_default}

                        else:
                            results_dictionary[cname] = parsed_result
                else:
                    # Not Multi the whole thing goes
                    if len(str(this_find)) == 0 and len_zero_default is not None and isinstance(len_zero_default, str):
                        # I have no result and I have a zero lenght default
                        results_dictionary[cname]["default"] = len_zero_default
                    else:
                        # I have a result or no result but no default
                        results_dictionary[cname]["default"] = str(this_find)

        else:
            results_dictionary = {"type" : {"subtype", "value"}}

        return results_dictionary

    def getall_collections(self):

        '''
        Cycles through all configured collections and runs a get_one for each one.
        '''

        myresults = dict()

        for this_collection in self.base_config_file["collections"].keys():
            self.logger.info("Collection {} Processing".format(this_collection))

            this_result = self.getone(this_collection, self.base_config_file["collections"][this_collection])

            myresults[this_collection] = this_result[this_collection]

        myresults["host_host"] = self.mown.to_dict(noargs=True)

        return myresults

    def gethostmeta(self):

        '''
        Takes the host metadata given and stores it puts defaults for nothing.

        mown
        '''

        mown_configs = {}

        if isinstance(self.host_configs["uri"], str):
            # Send My URI In Naked
            mown_configs = self.host_configs
        else:
            mown_configs = {**self.host_configs["uri"]}

            if "resource" not in self.host_configs.keys():
                mown_configs["resource"] = socket.getfqdn()

        if self.host_configs.get("do_aws", True) is True:
            # If AWS Service Detection is Not Turned Off in Configuration
            if self.ec2_data["is_ec2"] is True:
                mown_configs = {"uri" : self.ec2_data["uri"]}
            else:
                self.logger.debug("Not Detected as an AWS EC2 Instance.")

        self.logger.debug("MOWN as Configured: {}".format(mown_configs))

        my_mown = saltcell.mown.MoWN(**mown_configs)

        self.logger.info("Guessed MOWN : {}".format(my_mown.gen_uri()))

        return my_mown

    def get_aws_ec2_data(self, get_collections=False):

        '''
        Utilize ec_metadata endpoint to get ec2 Data
        '''

        response_doc = {"is_ec2" : False}


        if isinstance(self.host_configs["uri"], dict):
            given_args = self.host_configs["uri"].get("arguments", {})
        else:
            given_args = {}

        try:
            ec2_metadata.ec2_metadata.instance_id
        except Exception as ec2_error:
            self.logger.debug("EC2 Instance Detection Failed Likely not AWS : {}".format(ec2_error))
        else:

            self.logger.debug("AWS EC2 Instance Detected.")

            response_doc["is_ec2"] = True

            # Generate the ARN style URI
            response_doc["arn"] = "arn:ec2:{}:{}:instance/{}".format(ec2_metadata.ec2_metadata.region,
                                                                     ec2_metadata.ec2_metadata.account_id,
                                                                     ec2_metadata.ec2_metadata.instance_id)

            # Add Various Arguments
            response_doc["arn_args"] = {**given_args, **{"aws_ami_id" : ec2_metadata.ec2_metadata.ami_id,
                                                         "aws_avail_zone" : ec2_metadata.ec2_metadata.availability_zone,
                                                         "aws_instance_type" : ec2_metadata.ec2_metadata.instance_type,
                                                         "aws_private_hostname" : ec2_metadata.ec2_metadata.private_hostname,
                                                         "aws_public_hostname" : ec2_metadata.ec2_metadata.private_hostname,
                                                         "aws_guessed_arn" : response_doc["arn"]}}

            # Generate the ARN style URI
            response_doc["uri"] = "arn://ec2:{}:{}:instance/{}?{}".format(ec2_metadata.ec2_metadata.region,
                                                                          ec2_metadata.ec2_metadata.account_id,
                                                                          ec2_metadata.ec2_metadata.instance_id,
                                                                          urllib.parse.urlencode(response_doc["arn_args"]))

            self.logger.debug("Guessed AWS ARN based URI : {}".format(response_doc["arn"]))

            if get_collections is True:
                self.logger.debug("Grabbing AWS Collections.")

                aws_ipv4 = dict()
                aws_ipv6 = dict()
                aws_collection = {"ami_id" : ec2_metadata.ec2_metadata.ami_id,
                                  "avail_zone" : ec2_metadata.ec2_metadata.availability_zone,
                                  "iam_info" : str(ec2_metadata.ec2_metadata.iam_info),
                                  "instance_type" : ec2_metadata.ec2_metadata.instance_type,
                                  "private_hostname" : ec2_metadata.ec2_metadata.private_hostname,
                                  "public_hostname" : ec2_metadata.ec2_metadata.private_hostname,
                                  "security_groups" : ",".join(ec2_metadata.ec2_metadata.security_groups),
                                  "mac" : ec2_metadata.ec2_metadata.mac}

                try:
                    aws_collection["public_ipv4"] = ec2_metadata.ec2_metadata.public_ipv4
                except Exception:
                    self.logger.debug("AWS Detection no Public IPV4 Found.")
                else:
                    aws_ipv4[aws_collection["public_ipv4"]] = "IPV4"

                try:
                    aws_collection["public_ipv6"] = ec2_metadata.ec2_metadata.public_ipv6
                except Exception:
                    self.logger.debug("AWS Detection no Public IPV6 Found.")
                else:
                    aws_ipv6[aws_collection["public_ipv6"]] = "IPV6"

                try:
                    aws_collection["private_ipv4"] = ec2_metadata.ec2_metadata.private_ipv4
                except Exception:
                    self.logger.debug("AWS Detection no Private IPV4 Found.")
                else:
                    aws_ipv4[aws_collection["private_ipv4"]] = "IPV4"

                response_doc["aws_ipv4"] = aws_ipv4
                response_doc["aws_ipv6"] = aws_ipv6
                response_doc["aws_info"] = aws_collection

        return response_doc

    def getbasedata(self):

        '''
        Get the Basic Data like Collection Timestamp,
        A copy of the host data
        And any other meta data that shouldn't be stored as a collection
        '''

        basedata = self.mown.to_dict()

        basedata["collection_timestamp"] = int(time.time())

        return basedata

    def ipintel(self):

        '''
        Get's IPs from the IPV6 and IPV4 collection

        Future work, make configuralbe parsing
        '''

        found_intel = list()

        # Get Local Collected Addresses
        ipa_object = list()

        ipa_object.extend(list(self.collection_info.get("ipv4_addr", {}).keys()))
        ipa_object.extend(list(self.collection_info.get("ipv6_addr", {}).keys()))


        self.logger.debug("Raw Intel Object for this Host : \n{}".format(ipa_object))

        ipv4 = list()
        ipv6 = list()

        for this_unvalidated_ip in ipa_object:

            self.logger.debug("Doing IP Intell Checks against unvalidated IP : \t{}".format(this_unvalidated_ip))

            isipv4 = False
            isipv6 = False

            try:
                socket.inet_pton(socket.AF_INET, this_unvalidated_ip)
                isipv4 = True
            except OSError:
                # IPV4 Validation Failed, Try IPV6
                try:
                    socket.inet_pton(socket.AF_INET6, this_unvalidated_ip)
                    isipv6 = True
                except OSError:
                    pass
            finally:
                # After this checks let's see what showed up
                if isipv4 or isipv6:
                    # On or the other was true let's see if it's a private address
                    this_ip = ipaddress.ip_address(this_unvalidated_ip)

                    this_ip_good = True

                    if this_ip.is_private:
                        self.logger.debug("{} is a private address.".format(this_ip))
                        this_ip_good = False
                    elif this_ip.is_multicast:
                        self.logger.debug("{} is a multicast address.".format(this_ip))
                        this_ip_good = False
                    elif this_ip.is_unspecified:
                        self.logger.debug("{} is a unspecified (RFC 5735 or 2373) address.".format(this_ip))
                        this_ip_good = False
                    elif this_ip.is_loopback:
                        self.logger.debug("{} is a loopback address.".format(this_ip))
                        this_ip_good = False
                    elif this_ip.is_link_local:
                        self.logger.debug("{} is a link_local address.".format(this_ip))
                        this_ip_good = False
                    elif this_ip.is_global is False:
                        self.logger.debug("{} is not a Global IP Address.".format(this_ip))
                        this_ip_good = False

                    if this_ip_good:
                        # It's not a private IP so add it to the intel report
                        if isipv4:
                            ipv4.append(this_unvalidated_ip)
                        elif isipv6:
                            ipv6.append(this_unvalidated_ip)

        unduped_ipv4 = list(set(ipv4))
        unduped_ipv6 = list(set(ipv6))

        this_intel = dict()
        this_intel["host4"] = unduped_ipv4
        this_intel["host6"] = unduped_ipv6

        # Add all my IPs (even the non-public ones)
        for thing in ["host4", "host6"]:
            for found_intel_ip in this_intel[thing]:
                this_report = {"iptype" : thing,\
                               "ip" : found_intel_ip}

                found_intel.append(this_report)

        self.logger.info("Found {} Validated IPs for IP Intel.".format(len(found_intel)))
        self.logger.debug("IP Intel \n{}.".format(found_intel))

        return found_intel
