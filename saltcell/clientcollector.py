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
import re
import shlex

# Until I can workaround the salt-ssh python api problem.
import subprocess #nosec

import yaml
import requests
import pyjq
import jinja2
# For AWS Service Detection
#import ec2_metadata

import saltcell.mown

class Host:

    '''
    Collects Data Describing the Local Host using the configs specified.
    '''

    def __init__(self, minion_file="minion", base_config_file=False, local_cols=[False, None],
                 ipintel_configs=False, noupload=False, sapi_configs=False, **kwargs):

        self.logger = logging.getLogger("saltcell.clientcollector.Host")
        
        self.kwargs = kwargs

        self.noupload_runtime = noupload
        
        self.host_configs = kwargs.get("host_configs", dict())

        # Setup Things
        self.minion_file = minion_file

        self.salt_caller = self.start_minion()

        self.base_config_file = self.get_configs(base_config_file, local_cols)

        # Get Taxonomy Data
        self.mown = self.gethostmeta()
        self.basedata = self.getbasedata()
        
        self.default_grain = self.do_call("grains.items")

        # Get Collection Data
        self.collection_info = self.getall_collections()
        
        # Special Case EC2 Data
        #if self.ec2_data["is_ec2"] is True:
        #    self.collection_info["aws_info"] = self.ec2_data["aws_info"]

            # Add IP Data
        #    self.collection_info["ipv4_addr"] = {**self.collection_info["ipv4_addr"], **self.ec2_data["aws_ipv4"]}
        #    self.collection_info["ipv6_addr"] = {**self.collection_info["ipv6_addr"], **self.ec2_data["aws_ipv6"]}

        # Process IP Intel
        self.ipintel_configs = ipintel_configs

        # Uplad if I may
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

    def hydrate_obj(self, uh_obj, pump):
        
        '''
        Take the Thing given with the dictionary pump and
        turn it into a hydrated object
        '''
        
        do_json = False
        template_string = str(uh_obj)
        
        if isinstance(uh_obj, (dict, list)) is True:
            template_string = json.dumps(uh_obj)
            do_json = True
        
        template = jinja2.Environment(loader=jinja2.BaseLoader).from_string(template_string) #nosec
        
        rendered_string = template.render(**pump)
        
        if do_json is True:
            return_obj = json.loads(rendered_string)
        else:
            return_obj = rendered_string
        
        return return_obj

    def eval_upload(self):

        '''
        Evaluates and does the endpoint stuff
        '''

        response_code = False

        if self.noupload_runtime:
            self.logger.warning("Not uploading as noupload option specified at runtime, ignoring confiuration.")
        elif isinstance(self.sapi_configs, dict) and self.sapi_configs.get("sapi_do_api", False) is False:
            self.logger.warning("Not Uploading as sapi_do_api turned off in configs.")
        else:
            # It's Turned on
            post_data = self.todict()

            for this_endpoint in self.sapi_configs["sapi_endpoints"]:

                url = this_endpoint.get("url", False)
                name = this_endpoint.get("name", url)

                self.logger.debug("Uploading Data to : {}".format(name))

                headers = dict()

                if "sapi_token" in this_endpoint.keys() and "sapi_username" in this_endpoint.keys():
                    headers["Authorization"] = "{}:{}".format(str(this_endpoint["sapi_username"]), this_endpoint["sapi_token"])
                else:
                    self.logger.warning("sapi_username and/or sapi_token not set in config. No Default Auth added (normally).")

                headers.update(this_endpoint.get("custom_headers", {}))

                query_args = dict()
                query_args.update(this_endpoint.get("custom_query_args", {}))

                try:
                    post_request = requests.post(url, json=post_data, headers=headers, params=query_args)
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
        to_collect_items = dict()

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
                    with open(collection_file, "r") as collection_file_obj:
                        this_local_coll = yaml.safe_load(collection_file_obj)
                except Exception as collection_parse_error:
                    self.logger.error("Bad collection configuration file {} cannot parse: {}".format(collection_file))
                    self.logger.debug("Error : {}".format(collection_parse_error))
                else:
                    # I've read and parsed this file let's add the things
                    for this_new_coll_key, new_coll in this_local_coll.get("collections", {}).items():
                        if this_new_coll_key in to_collect_items["collections"].keys():
                            self.logger.warning("Ignoring Collection {} Defined in {} as a duplicate.".format(this_new_coll_key,
                                                                                                              collecion_file))
                        else:
                            to_collect_items["collections"][this_new_coll_key] = new_coll
        
        if len(to_collect_items.get("collections", dict()).keys()) == 0:
            self.logger.warning("No Collections Defined! This is abnormal.")

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
        import salt.client.ssh.client
        
        if self.kwargs.get("remote", False) is False:

            self.logger.debug("This is a local collection, start my Minion.")
            
            minion_opts = salt.config.minion_config(self.minion_file)

            salt_caller = salt.client.Caller(c_path=".", mopts=minion_opts)
        
        else:
            
            self.logger.debug("Remote Connection no Minion required.")
            salt_caller = None
        
        return salt_caller

    def do_call(self, saltfactor, saltargs=[], saltkwargs={}, jinja=False, dyn_jinja_dict=None):
        
        '''
        Does the Actual Call to Salt. Handles a Different Thing if this is a remote host
        we're trying to grab data for.
        '''
        
        this_find = None
        
        if jinja is True:
            saltfactor = self.hydrate_obj(saltfactor, dyn_jinja_dict)
            saltargs = self.hydrate_obj(list(saltargs), dyn_jinja_dict)
            saltkwargs = self.hydrate_obj(saltkwargs, dyn_jinja_dict)
        
        if self.kwargs.get("remote", False) is False:
            # Local Try
            try:
                this_find = self.salt_caller.function(saltfactor,
                                                      *saltargs,
                                                      **saltkwargs)
            except Exception as salt_call_error:
                self.logger.error("Unable to Run Salt Command for {}".format(saltfactor))
                self.logger.debug("Failed Commmand Full : {} {} {}".format(saltfactor, saltargs, saltkwargs))
                self.logger.debug("Error : {}".format(salt_call_error))
                this_find = None
            else:
                self.logger.debug("Return for {} : {}".format(saltfactor, this_find))
                
        else:
            # Okay so the python api is hella suspect Instead we're going to do some dirty and use the salt-ssh
            # CLI options
            
            if self.kwargs.get("hardcrash", True) is True:
                hardcrash = "--hard-crash"
            else:
                hardcrash = str()


            # What to Do about Host Keys. By default accept new keys on first seen basis
            #   and dump if there's a future mismatch.

            s_hkey = "--ignore-host-keys"

            if self.kwargs.get("strict_hostkeys", "known") == "strict":
                self.logger.debug("Respecting all Host key Limitations.")
                s_hkey = str()
            elif self.kwargs.get("strict_hostkeys", "known") == "known": 
                # Default Accepts New keys but blocks on Host Key Changes
                s_hkey = "--ignore-host-keys"
            elif self.kwargs.get("strict_hostkeys", "known") == "danger": 
                self.logger.warning("Remote Connection Totally Ignoring Host Key Checking Subsystmes.")
                s_hkey = "--no-host-keys"
            
            try:
                
                run_dir = self.kwargs.get("salt_ssh_basedir", "/etc/salt")
                
                if os.access(run_dir, os.W_OK) is False:
                    self.logger.error("Unable to Write to Run Directory : {}".format(run_dir))
                    self.logger.debug("Current Directory : {}".format(os.getcwd()))
                    
                    raise PermissionError("Unable to Access salt_ssh_basedir as Writeable")
                else:
                    self.logger.debug("Running command in Directory {}".format(run_dir))
                    
                relative_venv = self.kwargs.get("relative_venv", False)
                
                if isinstance(relative_venv, str):
                    self.logger.warning("Running Schedule3.py in a Relative VENV can be dangerous!")
                    self.logger.info("Releative Venv Command : {}".format(relative_venv))
                else:
                    self.logger.debug("Using the System's Python3")
                    relative_venv = str()
                
                    
                    
                if len(saltargs) > 0:
                    saltargs_string = shlex.quote(" ".join(saltargs))
                else:
                    saltargs_string = str()
                
                if len(saltkwargs.keys()) > 0:
                    saltkwargs_string = shlex.quote(" ".join(["{}={}".format(k, v) for k, v in saltkwargs.items()]))
                else:
                    saltkwargs_string = str()
                
                super_bad = "{} salt-ssh -W {} {} {} {} --output=json {}".format(relative_venv,
                                                                                 shlex.quote(self.kwargs.get("remote_host_id", None)),
                                                                                 shlex.quote(saltfactor),
                                                                                 saltargs_string,
                                                                                 saltkwargs_string,
                                                                                 hardcrash)
                
                #self.logger.debug("Debugging Salt-SSH Call\n\t{}".format(super_bad))
            
                # This looks bad. It's not the best. Ideally this would use the native salt
                run_args = {"shell" : True,
                            "stdout" : subprocess.PIPE,
                            "cwd" : run_dir,
                            "executable" : self.kwargs.get("shell", "/bin/bash"),
                            "timeout" : self.kwargs.get("remote_per_col_timeout", 60)}
                
                run_result = subprocess.run(super_bad, **run_args) #nosec 
                
            except subprocess.TimeoutExpired as timeout_error:
                self.logger.error("Collecting {} from {} timed out".format(saltfactor, 
                                                                           self.kwargs.get("remote_host_id", None)))
                self.logger.info("Timeout Setting : {}".format(run_args["timeout"]))
                self.logger.debug("Attempted Command : {}".format(super_bad))

            except Exception as salt_ssh_error:
                self.logger.error("Unable to Run Salt SSH command for {}".format(self.kwargs.get("remote_host_id", None)))
                self.logger.debug("Error : {}".format(salt_ssh_error))
                self.logger.debug("Attempted Command : {}".format(super_bad))
                this_find = None
            else:
                
                self.logger.debug(run_result.stdout)
                try:
                    run_result.check_returncode()
                except Exception as process_error:
                    self.logger.error("Unable to Run Salt SSH Command for {}".format(self.kwargs.get("remote_host_id", None)))
                    self.logger.warning("Error : {}".format(run_result.stderr))
                    this_find = None
                else:
                    # I have Results
                    try:
                        returned_results = json.loads(run_result.stdout.decode("utf-8"))
                        this_find = returned_results[self.kwargs.get("remote_host_id", None)]
                        
                    except Exception as read_result_json_error:
                        self.logger.error("Had Successful Saltssh But an Error when Parsing for {}".format(self.kwargs.get("remote_host_id", None)))
                        this_find = None
                    else:
                        self.logger.debug("Salt-ssh Find : \n{}".format(this_find))
        
        return this_find

    def getone(self, cname, collection, **kwargs):

        '''
        Logic to Collect one thing from the host

        Does the logic to use salt_caller to grab the data.
        '''

        results_dictionary = dict()
        results_dictionary[cname] = dict()

        is_multi = collection.get("multi", False)
        len_zero_default = collection.get("len_zero_default", None)

        if collection.get("salt", False) is True:
            
            try_fanout = True

            this_find = self.do_call(collection["saltfactor"],
                                     saltargs=collection.get("saltargs", list()),
                                     saltkwargs=collection.get("saltkwargs", dict()),
                                     jinja=kwargs.get("jinja", False),
                                     dyn_jinja_dict=kwargs.get("dyn_jinja_dict", None)
                                    )
            
            if this_find is None:
                self.logger.error("Unable to Run Salt Command for {}".format(cname))
                results_dictionary[cname]["default"] = collection.get("error_hint", "error")
                try_fanout = False
            else:

                self.logger.debug("Results for {} : \n{}".format(cname, json.dumps(this_find, default=str)))
                
                
                # Example Collection with snap packages for things in OS:Ubuntu
                if is_multi == "text":
                    # This is a Text Collection
                    
                    for this_line in this_find.splitlines():
                        try:
                            this_subtype = this_line.split()[0]
                            this_value = this_line.split()[1:]
                        except Exception as invalid_text_line:
                            self.logger.info("Invalid Text line {}".format(this_line))
                            self.logger.debug("Error : {}".format(invalid_text_line))
                        else:
                            results_dictionary[cname][this_subtype] = this_value
                        
                elif is_multi is True:
                    # Multi so do the JQ bits
                    try:
                        #parsed_result = jq.jq(collection["jq_parse"]).transform(this_find)
                        parsed_result = pyjq.first(collection["jq_parse"], this_find)
                    except Exception as Jq_Error:
                        self.logger.debug("When parsing {} Found results but JQ Parsing Failed.".format(Jq_Error))
                        results_dictionary[cname] = {"jq_error" : str(Jq_Error),
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
                
                if try_fanout is True:
                    for fanout_definition in collection.get("fan_out", list()):
                        
                        fanout_name = fanout_definition["name"]
                        
                        self.logger.info("Processing Fanout Definition {} on {}".format(fanout_name, cname))
                        
                        for subtype, value in results_dictionary[cname].items():
                            
                            dynamic_jinja = {"subtype" : subtype, "value" : value}
                            
                            synthetic_cname = "=>".join([cname, subtype, fanout_name])
                            
                            if self.eval_dg(fanout_definition.get("grain_limit", list())) is True:
                                
                                fanout_values = self.getone(synthetic_cname, fanout_definition,
                                                            jinja=True,
                                                            dyn_jinja_dict=dynamic_jinja)
                                
                                if fanout_values is not None:
                                    # Add to Results Dictionary
                                    results_dictionary[synthetic_cname] = fanout_values[synthetic_cname]
                                else:
                                    self.logger.warning("Unable to get fanout for {} {} on {}/{}".format(cname,
                                                                                                         synthetic_cname,
                                                                                                         subtype,
                                                                                                         value))
                            else:
                                
                                self.logger.debug("Fanout rule {} doesn't meet grain limitation.".format(fanout_name))
                else:
                    self.logger.debug("Fanout Not attempted for {}".format(cname))

        else:
            results_dictionary = {"type" : {"subtype", "value"}}

        return results_dictionary

    def getall_collections(self):

        """
        Cycles through all configured collections and runs a get_one for each one.
        """

        myresults = dict()

        for this_collection, this_collection_definition in self.base_config_file["collections"].items():
            
            self.logger.info("Collection {} Processing".format(this_collection))
            
            if self.eval_dg(this_collection_definition.get("grain_limit", list())) is True:

                this_result = self.getone(this_collection, this_collection_definition)
                
                # Default Collection
                myresults[this_collection] = this_result[this_collection]
                
                # Handle Fan Outs
                for fan_coll, fan_vals in this_result.items():
                    if fan_coll != this_collection:
                        
                        if fan_coll in myresults.keys():
                            self.logger.warning("Fan Out Collection {} Matches Primary Collection, Ignoring.".format(fan_coll))
                        else:
                            myresults[fan_coll] = fan_vals
                
                
            else:
                self.logger.info("Collection {} Ignored because of Grain Limitations.".format(this_collection))
            
        # Add Host_host results Special Case
        myresults["host_host"] = self.mown.to_dict(noargs=True)

        return myresults

    def gethostmeta(self):

        """
        Takes the host metadata given and stores it puts defaults for nothing.

        mown
        """

        mown_configs = {}

        if self.host_configs.get("do_platpi", True) is True:
            platform_guess = self.do_call("platpi.guess")
            self.logger.debug("Guessed Platform : {}".format(platform_guess))
        else:
            platform_guess = {"uri" : "unknown://::::unknown"}

        if isinstance(self.host_configs.get("uri", None), str):
            # Send My URI In Naked
            self.logger.debug("URI Given Explicitly Using That")
            mown_configs = self.host_configs
        elif isinstance(self.host_configs.get("uri", None), dict):
            self.logger.debug("URI Args Given in 'broken out' fashion Using That.")
            mown_configs = {**self.host_configs["uri"]}

            if "resource" not in self.host_configs.keys():
                self.logger.warning("Working around missing resource, setting resource to hostname")
                mown_configs["resource"] = socket.getfqdn()
        elif urllib.parse.urlparse(platform_guess.get("uri", "unknown://::::uknown")).scheme != "unknown":
            # If my Platform Guess Hasn't given me an Unknown Response Use the data
            # From my Platform Guess
            self.logger.debug("URI Taken from Platpi Guess")
            mown_configs = platform_guess["uri"]
        else:
            self.logger.warning("No URI/Hostname Given, Using A Naked URI based on Name only")
            mown_configs["resource"] = socket.getfqdn()

        self.logger.debug("MOWN as Configured: {}".format(mown_configs))

        my_mown = saltcell.mown.MoWN(**mown_configs)

        self.logger.info("Guessed MOWN : {}".format(my_mown.gen_uri()))

        return my_mown

    def get_aws_ec2_data(self, get_collections=False):

        ## TODO Ax This
        '''
        Utilize ec_metadata endpoint to get ec2 Data
        '''

        response_doc = {"is_ec2" : False}


        if isinstance(self.host_configs.get("uri", None), dict):
            given_args = self.host_configs["uri"].get("arguments", {})
        else:
            given_args = {}
            
        try:
            if self.kwargs.get("remote", False) is False:
                ec2_metadata.ec2_metadata.instance_id
            else:
                raise TypeError("Remote Platform Doesn't Support EC2 Detection.")
            
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

    def eval_dg(self, dg_def):
        
        '''
        Take a look at the grain definition and the default grains and see if we
        have a match
        '''
        
        this_pass = True
        
        for this_def in dg_def:
            
            this_jq = this_def.get("jq", None)
            this_regex = this_def.get("regex", None)
            this_negate = this_def.get("negate", False)
            
            c_eval = None
            
            if this_jq is not None:
                c_eval = pyjq.first(this_jq, self.default_grain)
                
            if c_eval is not None and this_regex is not None:
                c_eval = re.search(this_regex, c_eval)
            
            if c_eval is None and this_negate is True:
                continue
            elif c_eval is None:
                this_pass = False
                break
            elif c_eval is not None:
                # I've a result continue to next check
                continue
        
        return this_pass
                

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

        """
        Get's IPs from the IPV6 and IPV4 collection

        Future work, make configuralbe parsing
        """

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
