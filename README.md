# mitm-fuzzer
This is an implementation of a simple brute-force fuzzer for mitmproxy. It is implemented as an addon to mitmiproxy.

### What is mitmproxy
Mitmproxy is a swiss-army knife for debugging, testing, privacy measurements, and penetration testing. It can be used to intercept, inspect, modify and replay web traffic such as HTTP/1, HTTP/2, WebSockets, or any other SSL/TLS-protected protocols. You can prettify and decode a variety of message types ranging from HTML to Protobuf, intercept specific messages on-the-fly, modify them before they reach their destination, and replay them to a client or server later on.
### What is this fuzzer
This fuzzer is a mitmproxy addon used to perform brute-force attacks on GET or POST forms.
### How it works
It works by monitoring traffic and inspecting incoming requests. When a request parameter with a certain format type is detected, corresponding attack type is started.
### Prerequisites
- mitmproxy installed and running
- tkinter python module
- TODO: folders and fuzz input names
### How to start the program
Start mitmproxy: TODO
```sh
$ PLACEHOLDER
```
