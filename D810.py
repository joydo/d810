import os
import idaapi
import ida_hexrays
import ida_kernwin


from d810.conf import D810Configuration
from d810.manager import D810State, D810_LOG_DIR_NAME
from d810.log import configure_loggers, clear_logs


D810_VERSION = "0.1"

class D810Plugin(idaapi.plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "D-810"
    wanted_hotkey = "Ctrl-Shift-D"
    comment = "Interface to the D-810 plugin"
    help = ""
    initialized = False

    def __init__(self):
        super(D810Plugin, self).__init__()
        self.d810_config = None
        self.state = None
        self.initialized = False


    def reload_plugin(self):
        if self.initialized:
            self.term()

        self.d810_config = D810Configuration()

        #TO-DO: if [...].get raises an exception because log_dir is not found, handle exception
        real_log_dir = os.path.join(self.d810_config.get("log_dir"), D810_LOG_DIR_NAME)

        #TO-DO: if [...].get raises an exception because erase_logs_on_reload is not found, handle exception
        if self.d810_config.get("erase_logs_on_reload"):
            clear_logs(real_log_dir)

        configure_loggers(real_log_dir)
        self.state = D810State(self.d810_config)
        print("D-810 reloading...")
        self.state.start_plugin()
        self.initialized = True


    # IDA API methods: init, run, term
    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("D-810 need Hex-Rays decompiler. Skipping")
            return idaapi.PLUGIN_SKIP

        kv = ida_kernwin.get_kernel_version().split(".")
        if (int(kv[0]) < 7) or ((int(kv[0]) == 7) and (int(kv[1]) < 5)):
            print("D-810 need IDA version >= 7.5. Skipping")
            return idaapi.PLUGIN_SKIP
        print("D-810 initialized (version {0})".format(D810_VERSION))
        return idaapi.PLUGIN_OK


    def run(self, args):
        self.reload_plugin()


    def term(self):
        print("Terminating D-810...")
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


def PLUGIN_ENTRY():
    return D810Plugin()
