# `std.net.TcpListener`

[Home](README.md) · [Source file](File-std-net-ml-1989130045.md)

<a id="struct-struct-std-net-tcplistener-struct-tcplistener-std-net-ml-85126333"></a>
## TcpListener

```ml
struct TcpListener
```

Owned TCP listener that creates owned accepted connections.


Source: `std/net.ml:1023`

## Members

<a id="method-method-std-net-tcplistener-accept-function-accept-std-net-ml-1420514100"></a>
### accept

```ml
function accept()
```

Accept one connection and transfer ownership to its wrapper.


Source: `std/net.ml:1055`

<a id="method-method-std-net-tcplistener-acceptpeer-function-acceptpeer-std-net-ml-1895220488"></a>
### acceptPeer

```ml
function acceptPeer()
```

Return [connection, peerIp, peerPort].


Source: `std/net.ml:1063`

<a id="method-method-std-net-tcplistener-close-function-close-std-net-ml-111048440"></a>
### close

```ml
function close()
```

Close the listening socket once; repeat calls return true.


Source: `std/net.ml:1071`

<a id="field-field-std-net-tcplistener-closed-closed-std-net-ml-1621450730"></a>
### closed

```ml
closed
```

Whether the listening socket was closed.


Source: `std/net.ml:1027`

<a id="field-field-std-net-tcplistener-handle-handle-std-net-ml-1888570442"></a>
### handle

```ml
handle
```

Native listening socket.


Source: `std/net.ml:1025`

<a id="method-method-std-net-tcplistener-isclosed-function-isclosed-std-net-ml-1652573844"></a>
### isClosed

```ml
function isClosed()
```

Report the listening socket's closed state.


Source: `std/net.ml:1080`

<a id="static_method-static-method-std-net-tcplistener-listen-static-function-listen-port-backlog-std-net-ml-307585415"></a>
### listen

```ml
static function listen(port, backlog)
```

Listen on all IPv4 addresses.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | `dynamic` | — | Local port; zero asks the OS to choose one. |
| `backlog` | `dynamic` | — | Pending connection limit. |


Source: `std/net.ml:1032`

<a id="static_method-static-method-std-net-tcplistener-listenaddress-static-function-listenaddress-host-port-backlog-std-net-ml-383965123"></a>
### listenAddress

```ml
static function listenAddress(host, port, backlog)
```

Listen on a specific IPv4 address.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | `dynamic` | — | Dotted local IPv4 address. |
| `port` | `dynamic` | — | Local port. |
| `backlog` | `dynamic` | — | Pending connection limit. |


Source: `std/net.ml:1042`

<a id="method-method-std-net-tcplistener-rawhandle-function-rawhandle-std-net-ml-1151365744"></a>
### rawHandle

```ml
function rawHandle()
```

Borrow the listening handle without transferring ownership.


Source: `std/net.ml:1049`
