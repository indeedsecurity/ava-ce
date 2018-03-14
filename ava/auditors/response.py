from ava.common.auditor import _Auditor
from ava.handlers.passive import _PassiveHandler


# metadata
name = __name__
description = "audits each response"


class _ResponsePassiveHandler(_PassiveHandler):
    pass


class ResponseAuditor(_Auditor):
    """
    Audits each response of each vector. It audits by sending a request for each vector and inspecting the contents
    of each response. It implements _execute_check(), which is passed a chunk of vectors and returns a list of issues.
    """
    key = "response"
    name = "Responses"
    description = "Audits by inspecting the contents of each response"
    handlers = [
        _ResponsePassiveHandler
    ]
