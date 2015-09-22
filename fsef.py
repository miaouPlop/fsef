# coding=utf-8


from leaker import *
from exploiter import *
from process import *


context(arch="i386", os="linux")


class Fsef(object):
    def __init__(self, action="dump", method="global", null=False,
                 verbosity="info"):
        if action is None:
            action = "dump"
        self._action = action
        if method is None:
            method = "global"
        self._method = method
        if null is not True:
            null = False
        self._null = null
        if verbosity is None:
            verbosity = "info"
        self._verbosity = verbosity
        context.log_level = verbosity

    def _init_fsef(self):
        if self._action == "dump":
            self._leaker = Leaker(self._process, self._method,
                                  self._null, self._verbosity)
        elif self._action == "exploit":
            self._exploiter = Exploiter(self._process, self._verbosity)
        else:
            raise PwnlibException("Invalid action")

    def pwn(self, before_pwn=None, trigger_vuln=None, addr=None, 
            replacement=None, offset=None):
        if before_pwn is not None:
            self._process.hook_before_begin(before_pwn)
        if trigger_vuln is not None:
            self._process.hook_before_exploit(trigger_vuln, True)
        if self._action == "dump":
            self._leaker.dump()
        elif self._action == "exploit":
            self._exploiter.exploit(addr, replacement, offset)


class SshFsef(Fsef):
    def __init__(self, target, host, port, user, password,
                 action="dump", method="global", null=False,
                 arg="", byarg=False, verbosity="info"):
        Fsef.__init__(self, action, method, null, verbosity)
        self._target = target
        self._host = host
        if port is not None:
            if port.isdigit():
                if int(port) != 22:
                    self._port = int(port)
                else:
                    self._port = 22
            else:
                raise PwnlibException("Invalid port")
        else:
            self._port = 22
        self._user = user
        self._password = password
        self._target = target
        if arg is None:
            arg = ""
        if byarg is not True:
            byarg = False
        self._process = SshProcess(self._host, self._port, self._user,
                                   self._password, self._target, arg,
                                   byarg, self._verbosity)
        self._init_fsef()


class RemoteFsef(Fsef):
    def __init__(self, host, port,
                 action="dump", method="global", null=False,
                 verbosity="info"):
        Fsef.__init__(self, action, method, null, verbosity)
        self._host = host
        if port is not None:
            self._port = int(port)
        else:
            raise PwnlibException("Invalid port")
        self._process = RemoteProcess(host, port)
        self._init_fsef()


class LocalFsef(Fsef):
    def __init__(self, target,
                 action="dump", method="global", null=False,
                 arg="", byarg=False, verbosity="info"):
        Fsef.__init__(self, action, method, null, verbosity)
        self._target = target
        if arg is None:
            arg = ""
        if byarg is not True:
            byarg = False
        self._process = LocalProcess(self._target, arg, byarg,
                                     self._verbosity)
        self._init_fsef()
