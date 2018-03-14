import logging
import requests
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed


# configure logging
logger = logging.getLogger(__name__)


class _Auditor:
    """
    Parent Auditor class. It handles common utility functions, such as multiprocessing, threading, sending HTTP
    requests, generating issues, and printing status. Children audit specific HTTP aspects, such as parameters
    and URLs.
    """
    key = "auditor"
    name = "Auditor"
    description = "Parent auditor class"
    handlers = []

    def __init__(self, configs, checks, vectors):
        """Set AVA configs, checks, and vectors"""
        self._configs = configs
        self._checks = checks
        self._vectors = vectors
        self._session = requests.Session()
        self._handlers = [handler(configs, self.__class__, self._session) for handler in self.handlers]

    def _get_handler(self, check):
        """
        Gets the appropriate handler for the check. The handlers are instantiated in the self._handlers attribute.
        :param check: check object
        :return: handler object if found, None otherwise
        """
        # get handler
        for handler in self._handlers:
            if issubclass(check.__class__, handler.handles):
                return handler

        # default
        return None

    def _execute_cluster(self, check):
        """
        Executes threading for a given check. It creates n-number chunks of vectors for distribution among threads.
        Issues from each thread are combined and returned to the calling process. This calls _execute_check(), which
        should be implemented by each child Auditor.
        :param check: check object
        :return: issue list
        """
        issues = []

        # get handler
        handler = self._get_handler(check)

        # check handler
        if not handler:
            logger.debug("'%s' does not support '%s'. Ignoring.", self.name, check.name)
            return []

        # log message
        logger.info("%s : Checking %s.", self.name, check.name)

        # create pool
        threads = self._configs['threads']
        pool = ThreadPoolExecutor(threads)

        # create chunks
        chunks = [self._vectors[i::threads] for i in range(threads)]

        # spawn thread for each chunk
        futures = []
        for i in range(threads):
            future = pool.submit(handler.execute_check, check, chunks[i])
            futures.append(future)

        for future in as_completed(futures):
            issues.extend(future.result())

        return issues

    def run(self):
        """
        Executes multiprocessing for the auditor. Subprocesses are created for each check. Each subprocess then calls
        _execute_cluster() to distribute vectors among threads. Issues from each subprocess are combined and returned.
        :return: issue list
        """
        issues = []

        # create pool
        processes = self._configs['processes']
        pool = ProcessPoolExecutor(processes)

        # for each check into its own process
        futures = []
        for check in self._checks:
            future = pool.submit(self._execute_cluster, check)
            futures.append(future)

        # get issues
        for future in as_completed(futures):
            issues.extend(future.result())

        return issues
