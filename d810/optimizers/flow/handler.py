import logging
import idc

from d810.optimizers.handler import OptimizationRule, DEFAULT_FLOW_MATURITIES

logger = logging.getLogger('D810.optimizer')


class FlowOptimizationRule(OptimizationRule):
    def __init__(self):
        super().__init__()
        self.maturities = DEFAULT_FLOW_MATURITIES
        self.use_whitelist = False
        self.whitelisted_function_ea_list = []
        self.use_blacklist = False
        self.blacklisted_function_ea_list = []

    def configure(self, kwargs):
        super().configure(kwargs)
        self.use_whitelist = False
        self.whitelisted_function_ea_list = []
        self.use_blacklist = False
        self.blacklisted_function_ea_list = []
        if "whitelisted_functions" in self.config.keys():
            self.use_whitelist = True
            for func_ea in self.config["whitelisted_functions"]:
                self.whitelisted_function_ea_list.append(int(func_ea, 16))
            func_name_list = [idc.get_func_name(ea) for ea in self.whitelisted_function_ea_list]
            logger.info("Whitelisted functions for {0}: {1} -> {2}".format(self.__class__.__name__,
                                                                           self.whitelisted_function_ea_list,
                                                                           func_name_list))
        if "blacklisted_functions" in self.config.keys():
            self.use_blacklist = True
            for func_ea in self.config["whitelisted_functions"]:
                self.blacklisted_function_ea_list.append(int(func_ea, 16))
            func_name_list = [idc.get_func_name(ea) for ea in self.blacklisted_function_ea_list]
            logger.info("Blacklisted functions for {0}: {1} -> {2}".format(self.__class__.__name__,
                                                                           self.blacklisted_function_ea_list,
                                                                           func_name_list))
