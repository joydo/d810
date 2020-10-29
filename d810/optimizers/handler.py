from ida_hexrays import *

from d810.hexrays_formatters import string_to_maturity

DEFAULT_INSTRUCTION_MATURITIES = [MMAT_LOCOPT, MMAT_CALLS, MMAT_GLBOPT1]
DEFAULT_FLOW_MATURITIES = [MMAT_CALLS, MMAT_GLBOPT1]


class OptimizationRule(object):
    NAME = None
    DESCRIPTION = None

    def __init__(self):
        self.maturities = []
        self.config = {}
        self.log_dir = None

    def set_log_dir(self, log_dir):
        self.log_dir = log_dir

    def configure(self, kwargs):
        self.config = kwargs if kwargs is not None else {}
        if "maturities" in self.config.keys():
            self.maturities = [string_to_maturity(x) for x in self.config["maturities"]]

    @property
    def name(self):
        if self.NAME is not None:
            return self.NAME
        return self.__class__.__name__

    @property
    def description(self):
        if self.DESCRIPTION is not None:
            return self.DESCRIPTION
        return "No description available"
