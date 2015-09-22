# coding=utf-8


from pwn import ssh
from pwn import remote
from pwn import process
from pwn import context


class Process(object):
    def __init__(self, verbosity='info'):
        self._verbosity = verbosity
        self._hook_before_begin = None
        self._hook_before_exploit = None
        self._process = None
        self._byarg = False
        context.log_level = "error"

    def _start_process(self, cmd=""):
        raise NotImplementedError("")

    def send(self, cmd=""):
        if self._byarg:
            self._start_process(cmd)
        else:
            self._process.send(cmd)
        return self

    def recv(self, number=4096):
        context.log_level = "error"
        if self._process is not None:
            res = self._process.recv(number)
            if self._byarg:
                self._process.shutdown("recv")
                self._process.shutdown("send")
                self._process.close()
            context.log_level = self._verbosity
            return res
        else:
            context.log_level = self._verbosity
            return ""

    def reconnect(self):
        context.log_level = "error"
        if self._hook_before_begin is not None:
            self._hook_before_begin(self)
        return self

    def hook_before_begin(self, hook):
        self._hook_before_begin = hook
        hook(self)
        return self

    def hook_before_exploit(self, hook=None, register=False):
        if register is False:
            self._hook_before_exploit(self)
        else:
            self._hook_before_exploit = hook
        return self

    def interactive(self):
        self._process.interactive()


class SshProcess(Process):
    def __init__(self, host, port, user, password, target,
                 cmd="", byarg=False, verbosity='info'):
        Process.__init__(self, verbosity)
        context.log_level = "error"
        self._ssh = ssh(user, host, port, password)
        self._target = target
        if cmd != "":
            self._cmd = cmd.split(" ")
        else:
            self._cmd = []
        self._byarg = byarg
        if self._byarg is False:
            self._start_process()

    def _start_process(self, cmd=""):
        argv = [self._target]
        argv += self._cmd
        argv.append(cmd)
        self._process = self._ssh.process(argv)
        if self._hook_before_begin is not None:
            self._hook_before_begin(self)
        return self


class LocalProcess(Process):
    def __init__(self, target, cmd="", byarg=False, verbosity='info'):
        Process.__init__(self, verbosity)
        self._target = target
        self._process = None
        if cmd != "":
            self._cmd = cmd.split(" ")
        else:
            self._cmd = []
        self._byarg = byarg
        if self._byarg:
            self._start_process()
        self._verbosity = verbosity
        self._hook_before_begin = None
        self._hook_before_exploit = None

    def _start_process(self, cmd=""):
        argv = [self._target]
        argv += self._cmd
        argv.append(cmd)
        self._process = process(argv)
        if self._hook_before_begin is not None:
            self._hook_before_begin(self)
        return self


class RemoteProcess(Process):
    def __init__(self, host, port, verbosity='info'):
        Process.__init__(self, verbosity)
        self._host = host
        self._port = port
        self._process = None
        self._verbosity = verbosity
        self._start_process()
        self._hook_before_begin = None
        self._hook_before_exploit = None

    def _start_process(self, cmd=""):
        self._process = remote(self._host, self._port)
        context.log_level = self._verbosity
        return self

    def send(self, cmd=""):
        self._process.send(cmd)
        return self

    def reconnect(self):
        context.log_level = "error"
        self._start_process()
        if self._hook_before_begin is not None:
            self._hook_before_begin(self)
        context.log_level = self._verbosity
        return self
