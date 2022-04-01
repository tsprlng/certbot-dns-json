#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import sys
import datetime

from collections import OrderedDict

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot.plugins import common

from certbot_dns_json import *

logger = logging.getLogger(__name__)

class AutoJSONEncoder(json.JSONEncoder):
    """
    JSON encoder trying to_json() first
    """
    def default(self, obj):
        try:
            return obj.to_json()
        except AttributeError:
            return self.default_classic(obj)

    def default_classic(self, o):
        if isinstance(o, set):
            return list(o)
        elif isinstance(o, datetime.datetime):
            return (o - datetime.datetime(1970, 1, 1)).total_seconds()
        elif isinstance(o, bytes):
            return o.decode('UTF-8')
        else:
            return super(AutoJSONEncoder, self).default(o)


class Authenticator(common.Plugin, interfaces.Authenticator):
    """Manual Authenticator.

    This plugin requires user's manual intervention in setting up a HTTP
    server for solving http-01 challenges and thus does not need to be
    run as a privileged process. Alternatively shows instructions on how
    to use Python's built-in HTTP server.

    Script is also based on https://github.com/marcan/certbot-external

    """
    hidden = True

    description = "Manual challenge solver"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

        # Set up reverter
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()

    @classmethod
    def add_parser_arguments(cls, add):
        add("test-mode", action="store_true",
            help="Test mode. Executes the manual command in subprocess.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        # Non-interactive not yet supported
        if self.config.noninteractive_mode and not self.conf("test-mode"):
            raise errors.PluginError("Running manual mode non-interactively is not supported (yet)")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("It's like --manual for DNS challenges except it prints less.")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.DNS01]

    def perform(self, achalls):
        """
        Performs the actual challenge resolving.
        :param achalls:
        :return:
        """
        # pylint: disable=missing-docstring
        mapping = {"dns-01": self._perform_dns01_challenge}
        responses = []
        # TODO: group achalls by the same socket.gethostbyname(_ex)
        # and prompt only once per server (one "echo -n" per domain)

        for achall in achalls:
            responses.append(mapping[achall.typ](achall))

        input("Press return to verify...\n")
        return responses

    def cleanup(self, achalls):
        pass

    def _perform_dns01_challenge(self, achall):
        response, validation = achall.response_and_validation()

        json_data = OrderedDict()
        #json_data[FIELD_CMD] = COMMAND_PERFORM
        #json_data[FIELD_TYPE] = achall.chall.typ
        json_data[FIELD_DOMAIN] = achall.domain
        #json_data[FIELD_VALIDATION] = validation
        #json_data[FIELD_TXT_DOMAIN] = achall.validation_domain_name(achall.domain)
        json_data[FIELD_KEY_AUTH] = response.key_authorization

        json_data = self._json_sanitize_dict(json_data)

        self._json_out({'challenge':json_data}, True)

        return response

    #
    # Helper methods & UI
    #

    def _json_sanitize_dict(self, dictionary):
        """
        Sanitizes dictionary prior JSON serialization, handles byte string serialization
        :param dictionary:
        :return:
        """
        for key, val in list(dictionary.items()):
            # Not highly efficient, would be neater to clean up FIELD_TOKEN.
            # But if any of the others turn to bytes in the future, this will solve it:
            if isinstance(key, bytes):
                del dictionary[key]
                key = key.decode('UTF-8')
                dictionary[key] = val

            if isinstance(val, bytes):
                dictionary[key] = val.decode('UTF-8')

            elif type(val) in (list, tuple):
                nval = []
                for item in val:
                    if isinstance(item, bytes):
                        item = item.decode('UTF-8')
                    nval.append(item)
                dictionary[key] = nval
        return dictionary

    def _json_dumps(self, data, **kwargs):
        """
        Dumps data to the json string
        Using custom serializer by default
        :param data:
        :param kwargs:
        :return:
        """
        kwargs.setdefault('cls', AutoJSONEncoder)
        return json.dumps(data, **kwargs)

    def _json_out(self, data, new_line=False):
        """
        Dumps data as JSON to the stdout
        :param data:
        :param new_line:
        :return:
        """
        # pylint: disable=no-self-use
        json_str = self._json_dumps(data)
        if new_line:
            json_str += '\n'
        sys.stdout.write(json_str)
        sys.stdout.flush()
