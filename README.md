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
- a "dbs" directory inside dir where bffuzz.py is located which holds files with input values

### Config
Config file is called "config.py" and stores configuration for prefix parameter, database directory and logfile name.
### How to start the program

Assumptions:
- There is a running web app on localhost used for testing
- There is a bruteforce inputs file named "abc" located in "dbs" directory in bffuzz home dir
- Firefox is configured to proxy all HTTP/HTTPS traffic through 127.0.0.2:8080

First create "dbs" directory and appropriate input files. cd into "bffuzz.py" directory and do:
```
$ mkdir dbs
```
cd into created "dbs" dir and create a file containing input values which whill be used for bruteforcing. Each entry should be put in separate row using the newline delimiter.

Start mitmproxy with bffuzz addon:
```sh
$ mitmproxy -k -s bffuzz.py
```

In mitmproxy window, subscribe to 127.0.0.2 to filter all traffic except from 127.0.0.2:
```
: bffuzz.subscribe 127.0.0.2
```

In web application user input form window with 2 parameters (e.g. username and password parameters), hold one parameter constant and for the other parameter enter "fuzz_abc". Upon intercept, bffuzz will detect that this is a testing parameter and that it should perform bruteforcing against the detected testing parameter with input values from file <bffuzz home dir>/dbs/abc.