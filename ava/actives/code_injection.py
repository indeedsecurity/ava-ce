import os
import pickle
import time
from base64 import b64encode
from ava.common.check import _TimingCheck


# metadata
name = __name__
description = "checks for code injection"


class PythonCodeInjectionTimingCheck(_TimingCheck):
    """
    Checks for Python Code Injection by executing sleep statements. Payloads include exploits for dangerous functions
    eval(), exec(), and pickle.loads().
    """
    key = "code.timing.python"
    name = "Python Code Injection Timing"
    description = "checks for python code injection by executing delays"
    example = "__import__('time').sleep(9)"

    def __init__(self):
        """Define static payloads"""
        # eval and exec
        codes = ["__import__('time').sleep(9)", "__import__('os').system('sleep 9')"]

        # pickle classes
        class TimePayload:
            def __reduce__(self): return time.sleep, (9,)

        class SystemPayload:
            def __reduce__(self): return os.system, ("sleep 9",)

        # instantiate, pickle, and base64 classes
        pickles = [b64encode(pickle.dumps(clazz())).decode() for clazz in [TimePayload, SystemPayload]]

        # payloads
        self._payloads = [(payload, 9.00) for payload in codes + pickles]
