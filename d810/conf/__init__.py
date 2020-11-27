import os
import json


class D810Configuration(object):
    def __init__(self):
        self.config_dir = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
        self.config_file = os.path.join(self.config_dir, "options.json")
        with open(self.config_file, "r") as fp:
            self._options = json.load(fp)

    def get(self, name):
        if (name == "log_dir") and (self._options[name] is None):
            return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
        return self._options[name]

    def set(self, name, value):
        self._options[name] = value

    def save(self):
        with open(self.config_file, "w") as fp:
            json.dump(self._options, fp, indent=2)


class RuleConfiguration(object):
    def __init__(self, name=None, is_activated=False, config=None):
        self.name = name
        self.is_activated = is_activated
        self.config = config if config is not None else {}

    def to_dict(self):
        return {
            "name": self.name,
            "is_activated": self.is_activated,
            "config": self.config
        }

    @staticmethod
    def from_dict(kwargs):
        return RuleConfiguration(**kwargs)


class ProjectConfiguration(object):
    def __init__(self, path=None, description=None, ins_rules=None, blk_rules=None, conf_dir=None):
        self.path = path
        self.description = description
        self.conf_dir = conf_dir
        self.ins_rules = [] if ins_rules is None else ins_rules
        self.blk_rules = [] if blk_rules is None else blk_rules
        self.additional_configuration = {}

    def load(self):
        try:
            with open(self.path, "r") as fp:
                project_conf = json.load(fp)
        except FileNotFoundError as e:
            if self.conf_dir is not None:
                self.path = os.path.join(self.conf_dir, self.path)
                with open(self.path, "r") as fp:
                    project_conf = json.load(fp)

        self.description = project_conf["description"]
        self.ins_rules = [RuleConfiguration.from_dict(x) for x in project_conf["ins_rules"]]
        self.blk_rules = [RuleConfiguration.from_dict(x) for x in project_conf["blk_rules"]]

    def save(self):
        project_conf = {
            "description": self.description,
            "ins_rules": [x.to_dict() for x in self.ins_rules],
            "blk_rules": [x.to_dict() for x in self.blk_rules],
        }
        with open(self.path, "w") as fp:
            json.dump(project_conf, fp, indent=2)
