#!/usr/bin/env python3

'''
A URI Scheme for Denoting Hosts
'''

import logging
import urllib.parse
import re

class MoWN:

    '''
    Man o' War Notation. An arn compatible way to reference and store hosts in a system.
    '''

    _flavor_map = {"default" : {}}

    _notetype = "mown"

    def __init__(self, **kwargs):

        '''
        Vanilla Initiation
        '''

        self.logger = logging.getLogger("saltcell.mown.MoWN")

        self.partition = kwargs.get("partition", "")
        self.service = kwargs.get("service", "")
        self.region = kwargs.get("region", "")
        self.accountid = kwargs.get("accountid", "")
        self.resource_meta = {"resource" : kwargs.get("resource", "")}
        self.path = ""
        self.arguments = kwargs.get("arguments", {})

        if kwargs.get("uri", None) is not None:
            # Parse given uri and use that
            self.parse_uri(kwargs.get("uri"))

        self.uri = self.gen_uri(aws=kwargs.get("aws", False))

        self.logger.debug("New Object Generated URI of : {}".format(self.uri))

    def __str__(self):

        return str(self.gen_uri())

    def __repr__(self):

        return ("MoWN(partition={}, service={}, region={}, accountid={}, resource_meta={})".format(self.partition,
                                                                                                   self.service,
                                                                                                   self.region,
                                                                                                   self.accountid,
                                                                                                   self.gen_resource()))

    def to_dict(self, noargs=False, v2_compat=True):

        '''
        Returns a Dictionary Representation of the data in this thing
        '''

        return_dict = {}

        return_dict["resource"] = self.resource_meta["resource"]
        return_dict["partition"] = self.partition
        return_dict["service"] = self.service
        return_dict["region"] = self.region
        return_dict["accountid"] = self.accountid
        return_dict["mown_base"] = self.gen_uri(baseonly=True)
        return_dict["mown_full"] = self.gen_uri()

        if v2_compat is True:
            return_dict["uber_id"] = self.arguments.get("uber_id", None)
            return_dict["collection_hostname"] = self.resource_meta["resource"]
            return_dict["pop"] = self.region
            return_dict["srvtype"] = self.service
            return_dict["status"] = self.arguments.get("status", "unspecified")

        if noargs is False:
            return_dict["arguments"] = self.arguments

        return return_dict

    def parse_uri(self, given_mown):

        '''
        # Parsing the Given URI
        '''

        self.logger.debug("Parsing in URI of : {}".format(given_mown))

        parsed_uri = urllib.parse.urlparse(given_mown)

        netloc_flavor = parsed_uri.netloc
        path_flavor = parsed_uri.path

        # Let's deal with ARN Path's as a thing
        if len(parsed_uri.path) > 0:
            # I have a path starting at 1 get's rid of preceeding "/"
            broken_paths = parsed_uri.path[1:].split("/")


            # Always grab the first two as resource and resource qualifier (if they exist)
            # Because I join if I just have one entry it will come in as /resource
            # And if I have two as /resource/qualifier
            netloc_flavor = parsed_uri.netloc + "/{}".format("/".join(broken_paths[0:2]))

            path_flavor = ""
            if len(broken_paths) >= 3:
                # Grab additional items as path items
                path_flavor = "/{}".format("/".join(broken_paths[2:]))

        # Now I load the damn thing into my object's variables (Done by netloc_parse which calls
        # parse_resource_meta too
        self.netloc_parse(netloc_flavor)

        # Store my path as my path
        self.path = path_flavor

        # Store any given arguments
        self.arguments = {**self.arguments, **dict(urllib.parse.parse_qsl(parsed_uri.query))}

        # Record Source of Scheme as an Arg
        if parsed_uri.scheme != "mown":
            self.arguments["source_scheme"] = str(parsed_uri.scheme)

        return parsed_uri


    def gen_uri(self, baseonly=False, **kwargs):

        '''
        Generates a mown:// uri scheme to represent this asset.
        '''

        mown_uri = False

        # Arguments Given
        query = ""
        if baseonly is False:
            query = urllib.parse.urlencode(self.arguments, doseq=False)

        # if kwargs("otherintegration", False) is True
        #   Other Baked in Integrations Here.

        if mown_uri is False:

            # Try Default Pull from Args (Config)
            mown_uri = urllib.parse.urlunparse((self._notetype,
                                                self.netloc_create(),
                                                self.path,
                                                kwargs.get("params", ""),
                                                query,
                                                kwargs.get("fragment", "")))

        return mown_uri

    def netloc_create(self):

        '''
        Assembles the bits
        '''

        netloc = "{}:{}:{}:{}:{}".format((self.partition or ""),
                                         (self.service or ""),
                                         (self.region or ""),
                                         (self.accountid or ""),
                                         self.gen_resource())

        return netloc

    def netloc_parse(self, netloc):

        '''
        Netloc Parser

        Parses thenetloc and loads the bits
        '''
        split_netloc = re.split("[:/]", netloc)

        if len(split_netloc) < 5:
            raise ValueError("Unknown or uncompatible Format on Given URI.")

        # First part is simple
        self.partition, self.service, self.region, self.accountid = split_netloc[0:4]

        resource_string = ":{}".format(":".join(split_netloc[4:]))

        self.resource_meta = self.parse_resource_meta(resource_string)

        return (self.partition, self.service, self.region, self.accountid, self.resource_meta)

    def parse_resource_meta(self, given_resource_string):

        '''
        Take a Resource String and turn it into the appropriate dictionary
        '''

        # Splits the bits into their components based on the existence of / or : followed by text and shit
        seperated_functions = re.findall(r"([/:][\_\-\.\d\w]+)", given_resource_string)

        resource_meta = dict()

        # I swear this isn't as ugly as it looks
        if len(seperated_functions) == 1:
            # I only have a resource so store it a :resource
            resource_meta["rrsep"] = ":"
            resource_meta["resource"] = seperated_functions[0][1:]
        elif len(seperated_functions) == 2:
            # I have a resourcetype and a ressource so store it at :resourcetype[:/]resource
            resource_meta["resourcetype"] = seperated_functions[0][1:]
            resource_meta["rrsep"] = seperated_functions[1][0]
            resource_meta["resource"] = seperated_functions[1][1:]
        elif len(seperated_functions) >= 3:
            # I have a resourcetype, resource and a resource qualifier so store it as:
            # :resourcetype[:/]resource[:/]qualifier

            resource_meta["resourcetype"] = "".join(seperated_functions[0][1:])
            resource_meta["rrsep"] = seperated_functions[1][0]
            resource_meta["resource"] = seperated_functions[1][1:]
            resource_meta["rqsep"] = seperated_functions[2][0]
            resource_meta["qualifier"] = "".join(seperated_functions[2:])[1:]

        return resource_meta

    def gen_resource(self):

        '''
        Generate a Resource from my resource_meta
        '''

        if "resourcetype" not in self.resource_meta.keys() and "qualifier" not in self.resource_meta.keys():
            # Most Common Output
            resource_string = self.resource_meta["resource"]
        elif "qualifier" not in self.resource_meta.keys():
            # Must have resourcetype in this instance
            resource_string = "{}{}{}".format(self.resource_meta["resourcetype"],
                                              self.resource_meta.get("rrsep", "/"),
                                              self.resource_meta["resource"])
        else:
            # I have all three and seperator
            resource_string = "{}{}{}{}{}".format(self.resource_meta["resourcetype"],
                                                  self.resource_meta.get("rrsep", "/"),
                                                  self.resource_meta["resource"],
                                                  self.resource_meta.get("rqsep", ":"),
                                                  self.resource_meta["qualifier"])

        return resource_string
