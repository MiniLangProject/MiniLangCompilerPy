# `std/net.ml`

[Home](README.md) · [Files](Files.md)

Provides the std net package.

Package: [`std.net`](Package-std-net-1906042111.md)

Reachable from entry: **no**

## Declarations

<a id="global-global-std-net-wsaready-wsaready-std-net-ml-508432610"></a>
### _wsaReady

```ml
_wsaReady
```

init() and cleanup() serialize this process-wide Winsock ownership flag on the same recursive monitor. Ordinary socket operations may call init() concurrently, but applications must not call cleanup() while sockets remain in use.


Source: `std/net.ml:229`

<a id="constant-constant-std-net-af-inet-const-af-inet-2-std-net-ml-2055161241"></a>
### AF_INET

```ml
const AF_INET = 2
```

Portable socket constants plus the few target-specific option values.


Source: `std/net.ml:47`

<a id="function-function-std-net-cleanup-synchronized-function-cleanup-std-net-ml-1900488416"></a>
### cleanup

```ml
synchronized function cleanup()
```

Cleans up the platform socket layer.


Source: `std/net.ml:264`

<a id="function-function-std-net-close-function-close-sock-std-net-ml-2027943708"></a>
### close

```ml
function close(sock)
```

Closes a socket handle.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |


Source: `std/net.ml:742`

<a id="function-function-std-net-init-synchronized-function-init-std-net-ml-1993957128"></a>
### init

```ml
synchronized function init()
```

Initializes the platform socket layer. Safe to call multiple times.


Source: `std/net.ml:239`

<a id="constant-constant-std-net-invalid-socket-const-invalid-socket-1-std-net-ml-28841423"></a>
### INVALID_SOCKET

```ml
const INVALID_SOCKET = -1
```

Track the invalid socket value used by this standard-library module.


Source: `std/net.ml:59`

<a id="constant-constant-std-net-ipproto-tcp-const-ipproto-tcp-6-std-net-ml-187059453"></a>
### IPPROTO_TCP

```ml
const IPPROTO_TCP = 6
```

Track the ipproto tcp value used by this standard-library module.


Source: `std/net.ml:54`

<a id="constant-constant-std-net-ipproto-udp-const-ipproto-udp-17-std-net-ml-364496229"></a>
### IPPROTO_UDP

```ml
const IPPROTO_UDP = 17
```

Track the ipproto udp value used by this standard-library module.


Source: `std/net.ml:56`

<a id="function-function-std-net-lasterror-function-lasterror-std-net-ml-1066354328"></a>
### lastError

```ml
function lastError()
```

Returns the last platform socket error code.


Source: `std/net.ml:284`

<a id="constant-constant-std-net-max-portable-socket-timeout-ms-const-max-portable-socket-timeout-ms-2147483647-std-net-ml-1169126477"></a>
### MAX_PORTABLE_SOCKET_TIMEOUT_MS

```ml
const MAX_PORTABLE_SOCKET_TIMEOUT_MS = 2147483647
```

Track the max portable socket timeout ms value used by this standard-library module.


Source: `std/net.ml:22`

<a id="constant-constant-std-net-net-err-const-net-err-200-std-net-ml-1405001009"></a>
### NET_ERR

```ml
const NET_ERR = 200
```

Track the net err value used by this standard-library module.


Source: `std/net.ml:25`

<a id="constant-constant-std-net-sd-both-const-sd-both-2-std-net-ml-1523704177"></a>
### SD_BOTH

```ml
const SD_BOTH = 2
```

Track the sd both value used by this standard-library module.


Source: `std/net.ml:96`

<a id="constant-constant-std-net-sd-receive-const-sd-receive-0-std-net-ml-89766859"></a>
### SD_RECEIVE

```ml
const SD_RECEIVE = 0
```

Track the sd receive value used by this standard-library module.


Source: `std/net.ml:92`

<a id="constant-constant-std-net-sd-send-const-sd-send-1-std-net-ml-702702094"></a>
### SD_SEND

```ml
const SD_SEND = 1
```

Track the sd send value used by this standard-library module.


Source: `std/net.ml:94`

<a id="function-function-std-net-setkeepalive-function-setkeepalive-sock-enabled-std-net-ml-1531381615"></a>
### setKeepAlive

```ml
function setKeepAlive(sock, enabled)
```

Enable or disable TCP keepalive probes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `enabled` | `dynamic` | — | Value supplied for `enabled`. |


Source: `std/net.ml:474`

<a id="function-function-std-net-setnodelay-function-setnodelay-sock-enabled-std-net-ml-976341439"></a>
### setNoDelay

```ml
function setNoDelay(sock, enabled)
```

Disable or enable Nagle's algorithm for latency-sensitive protocols.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `enabled` | `dynamic` | — | Value supplied for `enabled`. |


Source: `std/net.ml:481`

<a id="function-function-std-net-setreceivetimeout-function-setreceivetimeout-sock-milliseconds-std-net-ml-2114040622"></a>
### setReceiveTimeout

```ml
function setReceiveTimeout(sock, milliseconds)
```

Configure the maximum blocking receive duration. Zero restores no timeout.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/net.ml:504`

<a id="function-function-std-net-setreuseaddress-function-setreuseaddress-sock-enabled-std-net-ml-620588191"></a>
### setReuseAddress

```ml
function setReuseAddress(sock, enabled)
```

Enable or disable address reuse on an existing socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `enabled` | `dynamic` | — | Value supplied for `enabled`. |


Source: `std/net.ml:429`

<a id="function-function-std-net-setsendtimeout-function-setsendtimeout-sock-milliseconds-std-net-ml-739144534"></a>
### setSendTimeout

```ml
function setSendTimeout(sock, milliseconds)
```

Configure the maximum blocking send duration. Zero restores no timeout.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/net.ml:511`

<a id="constant-constant-std-net-so-exclusiveaddruse-const-so-exclusiveaddruse-5-std-net-ml-281044779"></a>
### SO_EXCLUSIVEADDRUSE

```ml
const SO_EXCLUSIVEADDRUSE = -5
```

Track the so exclusiveaddruse value used by this standard-library module.


Source: `std/net.ml:69`

<a id="constant-constant-std-net-so-keepalive-const-so-keepalive-8-std-net-ml-577828755"></a>
### SO_KEEPALIVE

```ml
const SO_KEEPALIVE = 8
```

Track the so keepalive value used by this standard-library module.


Source: `std/net.ml:71`

<a id="constant-constant-std-net-so-rcvtimeo-const-so-rcvtimeo-4102-std-net-ml-526906682"></a>
### SO_RCVTIMEO

```ml
const SO_RCVTIMEO = 4102
```

Track the so rcvtimeo value used by this standard-library module.


Source: `std/net.ml:75`

<a id="constant-constant-std-net-so-reuseaddr-const-so-reuseaddr-4-std-net-ml-1192398905"></a>
### SO_REUSEADDR

```ml
const SO_REUSEADDR = 4
```

Track the so reuseaddr value used by this standard-library module.


Source: `std/net.ml:67`

<a id="constant-constant-std-net-so-sndtimeo-const-so-sndtimeo-4101-std-net-ml-1610942305"></a>
### SO_SNDTIMEO

```ml
const SO_SNDTIMEO = 4101
```

Track the so sndtimeo value used by this standard-library module.


Source: `std/net.ml:73`

<a id="constant-constant-std-net-sock-dgram-const-sock-dgram-2-std-net-ml-1372393675"></a>
### SOCK_DGRAM

```ml
const SOCK_DGRAM = 2
```

Track the sock dgram value used by this standard-library module.


Source: `std/net.ml:51`

<a id="constant-constant-std-net-sock-stream-const-sock-stream-1-std-net-ml-2014460758"></a>
### SOCK_STREAM

```ml
const SOCK_STREAM = 1
```

Track the sock stream value used by this standard-library module.


Source: `std/net.ml:49`

<a id="constant-constant-std-net-sockaddr-in-size-const-sockaddr-in-size-16-std-net-ml-1793932012"></a>
### SOCKADDR_IN_SIZE

```ml
const SOCKADDR_IN_SIZE = 16
```

Sockaddr_in size.


Source: `std/net.ml:102`

<a id="constant-constant-std-net-socket-error-const-socket-error-1-std-net-ml-2016210077"></a>
### SOCKET_ERROR

```ml
const SOCKET_ERROR = -1
```

Track the socket error value used by this standard-library module.


Source: `std/net.ml:61`

<a id="constant-constant-std-net-sol-socket-const-sol-socket-65535-std-net-ml-1028364697"></a>
### SOL_SOCKET

```ml
const SOL_SOCKET = 65535
```

Track the sol socket value used by this standard-library module.


Source: `std/net.ml:65`

<a id="constant-constant-std-net-tcp-nodelay-const-tcp-nodelay-1-std-net-ml-981076394"></a>
### TCP_NODELAY

```ml
const TCP_NODELAY = 1
```

Track the tcp nodelay value used by this standard-library module.


Source: `std/net.ml:89`

<a id="function-function-std-net-tcpaccept-function-tcpaccept-serversocket-std-net-ml-1658993728"></a>
### tcpAccept

```ml
function tcpAccept(serverSocket)
```

Accepts a client connection on a listening socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `serverSocket` | `dynamic` | — | Value supplied for `serverSocket`. |


Source: `std/net.ml:621`

<a id="function-function-std-net-tcpacceptpeer-function-tcpacceptpeer-serversocket-std-net-ml-324030640"></a>
### tcpAcceptPeer

```ml
function tcpAcceptPeer(serverSocket)
```

Accepts a client connection and returns peer info.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `serverSocket` | `dynamic` | — | Value supplied for `serverSocket`. |


Source: `std/net.ml:637`

<a id="function-function-std-net-tcpconnect-function-tcpconnect-host-port-std-net-ml-1793379633"></a>
### tcpConnect

```ml
function tcpConnect(host, port)
```

Creates a TCP connection to an IPv4 address (dotted) or "localhost".

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | `dynamic` | — | Value supplied for `host`. |
| `port` | `dynamic` | — | Value supplied for `port`. |


Source: `std/net.ml:522`

<a id="function-function-std-net-tcplisten-function-tcplisten-port-backlog-std-net-ml-2129811236"></a>
### tcpListen

```ml
function tcpListen(port, backlog)
```

Creates a TCP listening socket on 0.0.0.0:port.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | `dynamic` | — | Value supplied for `port`. |
| `backlog` | `dynamic` | — | Value supplied for `backlog`. |


Source: `std/net.ml:554`

<a id="function-function-std-net-tcplistenaddress-function-tcplistenaddress-host-port-backlog-std-net-ml-1591213138"></a>
### tcpListenAddress

```ml
function tcpListenAddress(host, port, backlog)
```

Create an IPv4 listener bound to an explicit dotted address.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | `dynamic` | — | Value supplied for `host`. |
| `port` | `dynamic` | — | Value supplied for `port`. |
| `backlog` | `dynamic` | — | Value supplied for `backlog`. |


Source: `std/net.ml:595`

<a id="function-function-std-net-tcprecv-function-tcprecv-sock-maxbytes-std-net-ml-76662791"></a>
### tcpRecv

```ml
function tcpRecv(sock, maxBytes)
```

Receives up to maxBytes from a TCP socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `maxBytes` | `dynamic` | — | Value supplied for `maxBytes`. |


Source: `std/net.ml:699`

<a id="function-function-std-net-tcpsendall-function-tcpsendall-sock-data-std-net-ml-931993120"></a>
### tcpSendAll

```ml
function tcpSendAll(sock, data)
```

Sends all bytes on a TCP socket (loops until everything is sent).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/net.ml:664`

<a id="function-function-std-net-tcpshutdown-function-tcpshutdown-sock-how-std-net-ml-386614342"></a>
### tcpShutdown

```ml
function tcpShutdown(sock, how)
```

Shuts down a TCP socket (best-effort).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `how` | `dynamic` | — | Value supplied for `how`. |


Source: `std/net.ml:728`

<a id="function-function-std-net-udpbind-function-udpbind-sock-port-std-net-ml-259267451"></a>
### udpBind

```ml
function udpBind(sock, port)
```

Binds a UDP socket to 0.0.0.0:port.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `port` | `dynamic` | — | Value supplied for `port`. |


Source: `std/net.ml:771`

<a id="function-function-std-net-udpopen-function-udpopen-std-net-ml-167881978"></a>
### udpOpen

```ml
function udpOpen()
```

Opens a UDP socket.


Source: `std/net.ml:755`

<a id="function-function-std-net-udprecvfrom-function-udprecvfrom-sock-maxbytes-std-net-ml-226021939"></a>
### udpRecvFrom

```ml
function udpRecvFrom(sock, maxBytes)
```

Receives a UDP datagram.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `maxBytes` | `dynamic` | — | Value supplied for `maxBytes`. |


Source: `std/net.ml:829`

<a id="function-function-std-net-udpsendto-function-udpsendto-sock-host-port-data-std-net-ml-2003989505"></a>
### udpSendTo

```ml
function udpSendTo(sock, host, port, data)
```

Sends a UDP datagram to an IPv4 host.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `sock` | `dynamic` | — | Value supplied for `sock`. |
| `host` | `dynamic` | — | Value supplied for `host`. |
| `port` | `dynamic` | — | Value supplied for `port`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/net.ml:796`

<a id="constant-constant-std-net-wsa-version-2-2-const-wsa-version-2-2-514-std-net-ml-1910707017"></a>
### WSA_VERSION_2_2

```ml
const WSA_VERSION_2_2 = 514
```

MAKEWORD(2,2).


Source: `std/net.ml:99`
