# `std.net.UdpSocket`

[Home](README.md) · [Source file](File-std-net-ml-1989130045.md)

<a id="struct-struct-std-net-udpsocket-struct-udpsocket-std-net-ml-989214751"></a>
## UdpSocket

```ml
struct UdpSocket
```

Owned UDP socket for datagram sends and receives.


Source: `std/net.ml:1086`

## Members

<a id="method-method-std-net-udpsocket-bind-function-bind-port-std-net-ml-16149974"></a>
### bind

```ml
function bind(port)
```

Bind to all local IPv4 addresses on the selected port.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | `dynamic` | — | Local UDP port; zero asks the OS to choose one. |


Source: `std/net.ml:1101`

<a id="method-method-std-net-udpsocket-close-function-close-std-net-ml-573356093"></a>
### close

```ml
function close()
```

Close the datagram socket once; repeat calls return true.


Source: `std/net.ml:1152`

<a id="field-field-std-net-udpsocket-closed-closed-std-net-ml-1054460201"></a>
### closed

```ml
closed
```

Whether the socket was closed.


Source: `std/net.ml:1090`

<a id="field-field-std-net-udpsocket-handle-handle-std-net-ml-1387425801"></a>
### handle

```ml
handle
```

Native datagram socket.


Source: `std/net.ml:1088`

<a id="method-method-std-net-udpsocket-isclosed-function-isclosed-std-net-ml-913489813"></a>
### isClosed

```ml
function isClosed()
```

Report the datagram socket's closed state.


Source: `std/net.ml:1161`

<a id="static_method-static-method-std-net-udpsocket-open-static-function-open-std-net-ml-1892000052"></a>
### open

```ml
static function open()
```

Create an unbound IPv4 datagram socket.


Source: `std/net.ml:1093`

<a id="method-method-std-net-udpsocket-rawhandle-function-rawhandle-std-net-ml-786980077"></a>
### rawHandle

```ml
function rawHandle()
```

Borrow the native handle without transferring ownership.


Source: `std/net.ml:1146`

<a id="method-method-std-net-udpsocket-receivefrom-function-receivefrom-maxbytes-std-net-ml-1219401990"></a>
### receiveFrom

```ml
function receiveFrom(maxBytes)
```

Receive [bytes, peerIp, peerPort].

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `maxBytes` | `dynamic` | — | Maximum datagram size. |


Source: `std/net.ml:1131`

<a id="method-method-std-net-udpsocket-receivefrominto-function-receivefrominto-destination-destinationoffset-count-std-net-ml-1258266449"></a>
### receiveFromInto

```ml
function receiveFromInto(destination, destinationOffset, count)
```

Receive into an existing buffer and return [count, peerIp, peerPort].

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `destination` | `dynamic` | — | Destination byte buffer. |
| `destinationOffset` | `dynamic` | — | First byte to overwrite. |
| `count` | `dynamic` | — | Maximum bytes to receive. |


Source: `std/net.ml:1140`

<a id="method-method-std-net-udpsocket-sendto-function-sendto-host-port-data-std-net-ml-1361609212"></a>
### sendTo

```ml
function sendTo(host, port, data)
```

Send one datagram to an IPv4 peer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | `dynamic` | — | Dotted IPv4 address or localhost. |
| `port` | `dynamic` | — | Destination port. |
| `data` | `dynamic` | — | Bytes or UTF-8 text to send. |


Source: `std/net.ml:1124`

<a id="method-method-std-net-udpsocket-setreceivetimeout-function-setreceivetimeout-milliseconds-std-net-ml-1810795555"></a>
### setReceiveTimeout

```ml
function setReceiveTimeout(milliseconds)
```

Set the datagram receive timeout in milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum wait time. |


Source: `std/net.ml:1108`

<a id="method-method-std-net-udpsocket-setsendtimeout-function-setsendtimeout-milliseconds-std-net-ml-708661663"></a>
### setSendTimeout

```ml
function setSendTimeout(milliseconds)
```

Set the datagram send timeout in milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum wait time. |


Source: `std/net.ml:1115`
