import argparse
from argparse import HelpFormatter


class _ArgumentHelpFormatter(HelpFormatter):

    def __init__(self, prog, indent_increment=2, max_help_position=35, width=90):
        """Call parent with increased max_help_position"""
        super().__init__(prog, indent_increment=indent_increment, max_help_position=max_help_position, width=width)

    def _format_action_invocation(self, action):
        """
        Simplifies help message. Positional arguments return "metavar". Optional arguments return "-s, --long".
        :param action: action object
        :return: format string
        """
        # positional
        if not action.option_strings:
            return action.dest

        # optional
        if action.nargs == 0:
            return ', '.join(action.option_strings)

        # optional with arguments
        return ', '.join(action.option_strings) + ' ' + action.dest.upper()


class ArgumentReader:

    def __init__(self, source):
        """Sets the reader's data source"""
        self._source = source

    def csv(self, value):
        """
        Converts a comma-separated string to a list.
        :param value: string value
        :return: values as list
        """
        # split by comma and strip
        csv = [v.strip() for v in value.split(',')]

        # filter empty
        return list(filter(None, csv))

    def dict(self, value):
        """
        Converts a key=value string to a list.
        :param value: string value
        :return: values as list
        """
        # check delimiter
        if '=' not in value:
            raise ValueError

        # split by key=value
        return value.split('=', 1)

    def parse(self):
        """
        Parses command-line arguments and returns them as a dictionary.
        :return: dictionary of args
        """
        program = "ava"
        usage = "{} [options...] hars".format(program)

        # set args
        # must be added to config.defaults and validated in config.generate()
        parser = argparse.ArgumentParser(prog=program, usage=usage, formatter_class=_ArgumentHelpFormatter)
        parser.add_argument('hars', help="har-formatted vector files", nargs='*')
        parser.add_argument('-l', '--list', help="show auditors and checks", action='store_true')
        parser.add_argument('--quiet', help="quiet console output", action='store_true')
        parser.add_argument('--debug', help="debug console output", action='store_true')
        parser.add_argument('-c', '--config', help="configuration file")
        parser.add_argument('-a', '--auditors', help="auditors as list", type=self.csv)
        parser.add_argument('-e', '--actives', help="active checks as list", type=self.csv)
        parser.add_argument('--blinds', help="blind check as 'name=callback'", action='append', type=self.dict)
        parser.add_argument('--passives', help="passive checks as list", type=self.csv)
        parser.add_argument('--set-payloads', help="set payloads as check=payload", type=self.dict, nargs='+')
        parser.add_argument('--add-payloads', help="add payloads as check=payload", type=self.dict, nargs='+')
        parser.add_argument('--show-examples', help="show examples of payloads", action='store_true')
        parser.add_argument('-o', '--report', help="json-formatted report file")
        parser.add_argument('--parameters', help="parameter as 'key=value'", action='append', type=self.dict)
        parser.add_argument('--cookies', help="cookie as 'key=value'", action='append', type=self.dict)
        parser.add_argument('--headers', help="header as 'key=value'", action='append', type=self.dict)
        parser.add_argument('--value', help="default parameter value")
        parser.add_argument('-x', '--excludes', help="exclude path pattern", action='append')
        parser.add_argument('-s', '--skips', help="skip parameter/cookie/header", action='append')
        parser.add_argument('--ignores', help="ignore passive matches", action='append')
        parser.add_argument('-n', '--domain', help="filter by domain")
        parser.add_argument('--agent', help="user-agent string")
        parser.add_argument('--timeout', help="timeout in seconds", type=int)
        parser.add_argument('-p', '--proxy', help="proxy as 'ip:port'")
        parser.add_argument('-m', '--processes', help="number of processes", type=int)
        parser.add_argument('-t', '--threads', help="number of threads", type=int)
        parser.add_argument('-f', '--follow', help="follow http redirects", action='store_true')
        parser.add_argument('-r', '--reduce', help="reduce duplicate vectors", action='store_true')
        parser.add_argument('-u', '--url', help="alternative url as 'hostname[:port]'")
        parser.add_argument('--summary', help="show scan summary", action='store_true')

        # parse args
        args = parser.parse_args(self._source)

        # combine dictionary types
        for name in ["blinds", "cookies", "headers", "parameters"]:
            values = getattr(args, name)
            setattr(args, name, dict(values) if values else None)

        # combine into list
        for name in ["set_payloads", "add_payloads"]:
            values = getattr(args, name)
            if values is None:
                continue
            combined = {}
            for key, value in values:
                if key not in combined:
                    combined[key] = []
                combined[key].append(value)
            setattr(args, name, combined)

        # convert
        return vars(args)
