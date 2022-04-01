#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Manual plugin on stereoids."""

import calendar
import collections
import json
import logging
import math
import os
import subprocess
import sys
import tempfile
import time
import datetime

from collections import OrderedDict

import zope.component
import zope.interface
from acme import challenges
from acme import errors as acme_errors

from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot.display import util as display_util
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


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
@zope.interface.implementer(interfaces.IReporter)
class Authenticator(common.Plugin):
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
        self._root = (tempfile.mkdtemp() if self.conf("test-mode")
                      else "/tmp/certbot")
        self._httpd = None
        self._start_time = calendar.timegm(time.gmtime())
        self._handler_file_problem = False

        # Set up reverter
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()

        # Reporter
        self.orig_reporter = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("test-mode", action="store_true",
            help="Test mode. Executes the manual command in subprocess.")
        add("public-ip-logging-ok", action="store_true",
            help="Automatically allows public IP logging.")
        add("text-mode", action="store_true",
            help="Original text mode, by default turned off, produces JSON challenges")
        add("handler", default=None,
            help="Handler program that takes the action. Data is transferred in ENV vars")
        add("dehydrated-dns", action="store_true",
            help="Switches handler mode to Dehydrated DNS compatible version")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        # Re-register reporter - json only report
        self.orig_reporter = zope.component.getUtility(interfaces.IReporter)
        zope.component.provideUtility(self, provides=interfaces.IReporter)

        # Re-register displayer - stderr only displayer
        #displayer = display_util.NoninteractiveDisplay(sys.stderr)
        displayer = display_util.FileDisplay(sys.stderr, False)
        zope.component.provideUtility(displayer)

        # Non-interactive not yet supported
        if self.config.noninteractive_mode and not self.conf("test-mode"):
            raise errors.PluginError("Running manual mode non-interactively is not supported (yet)")
        if not self._is_handler_mode() and self._is_dehydrated_dns():
            raise errors.PluginError("dehydrated-dns switch is allowed only with handler specified")

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

        if self._is_classic_handler_mode() and self._call_handler("pre-perform") is None:
            raise errors.PluginError("Error in calling the handler to do the pre-perform (challenge) stage")

        for achall in achalls:
            responses.append(mapping[achall.typ](achall))

        if self._is_classic_handler_mode() and self._call_handler("post-perform") is None:
            raise errors.PluginError("Error in calling the handler to do the post-perform (challenge) stage")

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
    # Installer section
    #

    def get_all_names(self):
        return []

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        cur_record = OrderedDict()
        cur_record[FIELD_CMD] = COMMAND_DEPLOY_CERT
        cur_record[FIELD_DOMAIN] = domain
        cur_record[FIELD_CERT_PATH] = cert_path
        cur_record[FIELD_KEY_PATH] = key_path
        cur_record[FIELD_CHAIN_PATH] = chain_path
        cur_record[FIELD_FULLCHAIN_PATH] = fullchain_path
        cur_record[FIELD_TIMESTAMP] = self._start_time
        cur_record[FIELD_CERT_TIMESTAMP] = self._get_file_mtime(cert_path)

        if self._is_json_mode() or self._is_handler_mode():
            self._json_out(cur_record, True)

        hook_cmd = "deploy_cert" if cur_record[FIELD_CERT_TIMESTAMP] >= cur_record[FIELD_TIMESTAMP] else 'unchanged_cert'
        if self._is_handler_mode() and self._call_handler(hook_cmd, **(self._get_json_to_kwargs(cur_record))) is None:
            raise errors.PluginError("Error in calling the handler to do the deploy_cert stage")
        pass

    def enhance(self, domain, enhancement, options=None):
        pass  # pragma: no cover

    def supported_enhancements(self):
        return []

    def get_all_certs_keys(self):
        return []

    def save(self, title=None, temporary=False):
        cur_record = OrderedDict()
        cur_record[FIELD_CMD] = COMMAND_SAVE
        cur_record['title'] = title
        cur_record['temporary'] = temporary
        if self._is_json_mode() or self._is_handler_mode():
            self._json_out(cur_record, True)

    def rollback_checkpoints(self, rollback=1):
       pass  # pragma: no cover

    def recovery_routine(self):
        pass  # pragma: no cover

    def view_config_changes(self):
        pass  # pragma: no cover

    def config_test(self):
        pass  # pragma: no cover

    def restart(self):
        cur_record = OrderedDict()
        cur_record[FIELD_CMD] = COMMAND_RESTART
        if self._is_json_mode() or self._is_handler_mode():
            self._json_out(cur_record, True)

    #
    # Caller
    #

    def _call_handler(self, command, *args, **kwargs):
        """
        Invoking the handler script
        :param command:
        :param args:
        :param kwargs:
        :return:
        """
        env = dict(os.environ)
        env.update(kwargs)

        # Dehydrated compatibility mode - translate commands
        if self._is_dehydrated_dns():
            auth_cmd_map = {'perform': 'deploy_challenge', 'cleanup': 'clean_challenge'}
            install_cmd_map = {'deploy_cert': 'deploy_cert', 'unchanged_cert': 'unchanged_cert'}

            if command in auth_cmd_map:
                command = auth_cmd_map[command]
                args = list(args) + [kwargs.get(FIELD_DOMAIN), kwargs.get(FIELD_TOKEN), kwargs.get(FIELD_VALIDATION)]

            elif command in install_cmd_map:
                command = install_cmd_map[command]
                args = list(args) + [kwargs.get(FIELD_DOMAIN), kwargs.get(FIELD_KEY_PATH), kwargs.get(FIELD_CERT_PATH),
                                     kwargs.get(FIELD_FULLCHAIN_PATH), kwargs.get(FIELD_CHAIN_PATH)]

                if command == 'deploy_cert':
                    args.append(kwargs.get(FIELD_TIMESTAMP))

            else:
                logger.info("Dehydrated mode does not support this handler command: %s" % command)

        proc = None
        stdout, stderr = None, None
        arg_list = [self._get_handler(), command] + list(args)

        # Check if the handler exists
        if not os.path.isfile(self._get_handler()):
            self._handler_file_problem = True
            logger.error("Handler script file `%s` not found. Absolute path: %s"
                         % (self._get_handler(), self._try_get_abs_path(self._get_handler())))

            if os.path.exists(self._get_handler()):
                logger.error("Handler script `%s` is not a file" % self._get_handler())

            return None

        # Check if is executable
        # Still try to run, throw an exception only if problem really did occur.
        exec_problem = not self._is_file_executable(self._get_handler())

        # The handler invocation
        try:
            proc = subprocess.Popen(arg_list,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    env=env)
            stdout, stderr = proc.communicate()

            # Handler processing
            if proc.returncode != 0:
                if stdout.strip() == "NotImplemented":
                    logger.warning("Handler script does not implement the command %s\n - Stderr: \n%s",
                                   command, stderr)
                    return NotImplemented

                else:
                    logger.error("Handler script failed!\n - Stdout: \n%s\n - Stderr: \n%s", stdout, stderr)
                    return None

            else:
                    logger.info("Handler output (%s):\n - Stdout: \n%s\n - Stderr: \n%s",
                                command, stdout, stderr)
            return stdout

        except Exception as e:
            self._handler_file_problem = True
            logger.error("Handler script invocation failed with an exception. \n - Script: %s\n - Exception: %s"
                         % (' '.join(arg_list), e))
            if exec_problem:
                logger.error("Handler script %s does not have the executable permission set so it cannot be executed. "
                             "\n - Try running: chmod +x \"%s\" " % (self._get_handler(), self._try_get_abs_path(self._get_handler())))
            else:
                logger.warning("Make sure the handler file exists and is executable (+x permission on a Posix system)")

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

    def _is_file_executable(self, fpath):
        """
        Returns true if the given file is executable (+x flag)
        :param fpath:
        :return:
        """
        if os.name.lower() == 'posix':
            try:
                return os.access(fpath, os.X_OK)
            except:
                return False
        else:
            return True

    def _try_get_abs_path(self, fpath):
        """
        Returns absolute path, catching possible exceptions.
        :param fpath:
        :return:
        """
        try:
            return os.path.abspath(fpath)
        except:
            return fpath

    def _is_text_mode(self):
        """
        Returns true if text-mode is selected
        :return:
        """
        return self.conf("text-mode")

    def _is_json_mode(self):
        """
        Returns true if json mode is selected
        :return:
        """
        return not self._is_text_mode() and not self._is_handler_mode()

    def _is_handler_mode(self):
        """
        Returns true if handler mode is selected
        :return:
        """
        return self.conf("handler") is not None

    def _is_handler_broken(self):
        """
        Returns true if the handler file cannot be executed - exception was thrown
        :return:
        """
        return self._handler_file_problem

    def _is_classic_handler_mode(self):
        """
        Handler mode && not dehydrated
        :return:
        """
        return self._is_handler_mode() and not self._is_dehydrated_dns()

    def _get_handler(self):
        """
        Returns handler script path - from CLI argument
        :return:
        """
        return self.conf("handler")

    def _is_dehydrated_dns(self):
        """
        Returns true if dehydrated dns mode is used
        :return:
        """
        return self.conf("dehydrated-dns")

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
