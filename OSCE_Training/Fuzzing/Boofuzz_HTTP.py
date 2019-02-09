# Simple HTTP Fuzzer utilizing boofuzz!
# By w4fz5uck5
# pip install boofuzz

from boofuzz import * 
import time

session = Session(
    target=Target(
        connection=SocketConnection("192.168.0.111", 80, proto='tcp', send_timeout=10.0, recv_timeout=10.0)))

s_initialize("get")
s_static("GET ")
s_string("AAAA")
s_static("HTTP/1.1\r\n")
s_static("Host: 127.0.0.1:80\r\n")
s_static("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.96 Safari/537.36\r\n")
s_static("Cookies: A=BBBB\r\n")
s_static("Connection: close\r\n\r\n")

s_initialize("host")
s_static("GET index.html HTTP/1.1\r\n")
s_static("Host: ")
s_string("AAAA")
s_static(":80\r\n")
s_static("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.96 Safari/537.36\r\n")
s_static("Cookies: A=BBBB\r\n")
s_static("Connection: close\r\n\r\n")

s_initialize("user-agent")
s_static("GET index.html HTTP/1.1\r\n")
s_static("Host: 127.0.0.1:80\r\n")
s_static("User-Agent: ")
s_string("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.96 Safari/537.36")
s_static("\r\n")
s_static("Cookies: A=BBBB\r\n")
s_static("Connection: close\r\n\r\n")

s_initialize("cookies")
s_static("GET index.html HTTP/1.1\r\n")
s_static("Host: 127.0.0.1:80\r\n")
s_static("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.96 Safari/537.36\r\n")
s_static("Cookies:")
s_string("A=BBBB")
s_static("\r\n")
s_static("Connection: close\r\n\r\n")

s_initialize("connection")
s_static("GET index.html HTTP/1.1\r\n")
s_static("Host: 127.0.0.1:80\r\n")
s_static("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.96 Safari/537.36\r\n")
s_static("Cookies: A=BBBB\r\n")
s_static("Connection: ")
s_string("AAAA")
s_static("\r\n\r\n")

#session.connect(s_get("get"))
#session.connect(s_get("host"))
#session.connect(s_get("user-agent"))
#session.connect(s_get("cookies"))
session.connect(s_get("connection"))

session.fuzz()
