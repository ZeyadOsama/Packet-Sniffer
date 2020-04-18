# Packet Sniffer
<p>
  <img src="https://img.shields.io/pypi/status/Django.svg"/>
</p>
<p>
A simple packet sniffer in Python can be created with the help socket module. We can use the raw socket type to get the packets. A raw socket provides access to the underlying protocols, which support socket abstractions. Since raw sockets are part of the internet socket API, they can only be used to generate and receive IP packets.
</p>

<img alt="packet_sniffer" src="https://user-images.githubusercontent.com/30150819/79671094-f8bf8f00-81c7-11ea-94a6-71a7a4eeef19.png"/>

## Synopsis
This is a python implementation of sniffing packets using sockets.

## Getting Ready
As some behaviors of the socket module depend on the operating system socket API and there is no uniform API for using a raw socket under a different operating system, we need to use a <b>Linux OS</b> to run this script. So, if you are using Windows or macOS, please make sure to run this script inside a virtual Linux environment. Also, most operating systems <b>require root access</b> to use raw socket APIs.

## Code Flow

### 1. Initilizing Sockets
Here are the steps to create a basic packet sniffer with socket module:
1. Import the required modules:
``` python
import socket
```
2. Create a raw socket
``` python
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
```
#### Raw Socket Paramters
Both reading and writing to a raw socket require creating a raw socket first.
* The family parameter for a socket describes the address family of the socket. Here we use the ```INET``` (used for IPv4) family raw socket.
* The next parameter passed is the type of the socket. For a raw socket we need ```SOCK_RAW```.
* The last parameter is the protocol of the packet. This protocol number is defined by the Internet Assigned Numbers Authority (IANA). We have to be aware of the family of the socket; then we can only choose a protocol. As we selected ```AF_INET``` (IPV4), we can only select IP-based protocols.

3. Start an infinite loop to receive data from the socket
``` python
while True:
  packet, addr = s.recvfrom(65565)
```
<b>N.B.</b> The ```recvfrom``` method in the ```socket``` module helps us to receive all the data from the socket. The parameter passed is the buffer size. Note that ```65565``` is the maximum buffer size.

<br>

### 2. Parsing Recived Packet
Now we can try to parse the data that we sniffed, and unpack the headers. To parse a packet, we need to have an idea of the Ethernet frame and the packet headers of the IP.

#### Parsing IP header 
An IP header typically looks like the following:

```
0                   1                   2                   3   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<b>N.B.</b> Please refer to the <a href="https://tools.ietf.org/html/rfc791">IP RFC</a> for detailed information.

<br>

#### Parsing TCP header 
A TCP header typically looks like the following:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

<b>N.B.</b> Please refer to the <a href="https://tools.ietf.org/html/rfc793">TCP RFC</a> for detailed information.


## API Reference
* All about Python ```sockets``` [here](https://docs.python.org/2/library/socket.html)
* All about Python ```structs``` [here](https://docs.python.org/2/library/struct.html)
* All about Python ```sys``` [here](https://docs.python.org/2/library/sys.html)

## Tests
You can find test cases to check the correctness of parsing [here](https://github.com/ZeyadOsama/http-packet-stealer/blob/master/test_cases.py)

## Usage
```
git clone <repo-url>
sudo python3 <path>\main.py
```
<b>N.B.</b> Doing `sudo` is important as you should have `root` priviledges.
