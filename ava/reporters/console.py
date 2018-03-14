
class TableReporter:
    """
    Reports issues in table format to the console. This is used when displaying results at the end of a scan.
    """
    _headers = ["Auditor", "Check", "URL", "Target", "Value"]
    _padding = 2

    def __init__(self, results, auditors, checks):
        """Sets the reporter's collection of results"""
        self._auditors = auditors
        self._checks = checks

        # calculated values (in this order)
        self._results = self._convert_results(results)
        self._columns = len(self._headers)
        self._widths = self._calculate_widths()

    def _convert_results(self, results):
        """
        Convert results dictionary to a results list suitable for table rows.
        :param results: results as dictionary
        :return: results as list
        """
        issues = []
        lookup = {}

        # generate lookup
        lookup.update({a.key: a.name for a in self._auditors})
        lookup.update({c.key: c.name for c in self._checks})

        # convert dictionary to list
        for issue in results:
            auditor = lookup.get(issue['auditor'])
            check = lookup.get(issue['check'])
            url = issue['vector']['url']
            target = issue['target']
            value = issue['value']
            issues.append([auditor, check, url, target, value])

        return issues

    def _calculate_widths(self):
        """
        Calculates the width for each column. The width is derived from the longest element in each row plus the set
        padding for the table.
        :return: width size for each column
        """
        widths = []

        # combine headers and results
        rows = [self._headers] + self._results

        # get longest value for each column
        for c in range(self._columns):
            width = max([len(row[c]) for row in rows])
            widths.insert(c, width + self._padding)

        return widths

    def _print_separator(self):
        """
        Prints a separator row of plus signs and dashes, such as +----+----+----+.
        """
        # print separator
        for c in range(self._columns):
            if c == 0:
                print('+', end='')
            print('-' * self._widths[c], end='')
            print('+', end='')
        print('')

    def _print_row(self, row):
        """
        Prints a row of the table. Elements are separated by pipe symbols, |.
        :param row: row as list
        """
        # print row
        for c in range(self._columns):
            if c == 0:
                print('|', end='')
            print(row[c].center(self._widths[c]), end='')
            print('|', end='')
        print('')

    def report(self):
        """
        Generates a table report from collection of results.
        """
        # start table
        self._print_separator()

        # print headers
        self._print_row(self._headers)

        # separate headers and results
        self._print_separator()

        # print results
        for issue in self._results:
            self._print_row(issue)

        # close table
        self._print_separator()
