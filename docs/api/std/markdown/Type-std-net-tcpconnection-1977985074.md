# `std.net.TcpConnection`

[Home](README.md) · [Source file](File-std-net-ml-1989130045.md)

<a id="struct-struct-std-net-tcpconnection-struct-tcpconnection-std-net-ml-1334326733"></a>
## TcpConnection

```ml
struct TcpConnection
```

Owned TCP connection with explicit, idempotent close.


Source: `std/net.ml:927`

## Members

<a id="method-method-std-net-tcpconnection-close-function-close-std-net-ml-687259312"></a>
### close

```ml
function close()
```

Close the socket once; repeat calls return true.


Source: `std/net.ml:1008`

<a id="field-field-std-net-tcpconnection-closed-closed-std-net-ml-1477213050"></a>
### closed

```ml
closed
```

Whether the socket was closed through this wrapper.


Source: `std/net.ml:931`

<a id="static_method-static-method-std-net-tcpconnection-connect-static-function-connect-host-port-std-net-ml-1609802726"></a>
### connect

```ml
static function connect(host, port)
```

Connect to an IPv4 host and take ownership of the returned socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | `dynamic` | — | Dotted IPv4 address or localhost. |
| `port` | `dynamic` | — | Remote TCP port. |


Source: `std/net.ml:936`

<a id="field-field-std-net-tcpconnection-handle-handle-std-net-ml-819703386"></a>
### handle

```ml
handle
```

Native socket owned by this connection.


Source: `std/net.ml:929`

<a id="method-method-std-net-tcpconnection-isclosed-function-isclosed-std-net-ml-76686828"></a>
### isClosed

```ml
function isClosed()
```

Report the TCP connection's closed state.


Source: `std/net.ml:1017`

<a id="method-method-std-net-tcpconnection-rawhandle-function-rawhandle-std-net-ml-728838824"></a>
### rawHandle

```ml
function rawHandle()
```

Borrow the native handle for a call such as tls.connect(). The caller must not close this borrowed handle separately.


Source: `std/net.ml:944`

<a id="method-method-std-net-tcpconnection-receive-function-receive-maxbytes-std-net-ml-379140399"></a>
### receive

```ml
function receive(maxBytes)
```

Receive at most maxBytes into a newly allocated buffer.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `maxBytes` | `dynamic` | — | Maximum bytes to receive. |


Source: `std/net.ml:958`

<a id="method-method-std-net-tcpconnection-receiveinto-function-receiveinto-destination-destinationoffset-count-std-net-ml-1783320186"></a>
### receiveInto

```ml
function receiveInto(destination, destinationOffset, count)
```

Receive into a caller-owned buffer without copying.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `destination` | `dynamic` | — | Destination byte buffer. |
| `destinationOffset` | `dynamic` | — | First byte to overwrite. |
| `count` | `dynamic` | — | Maximum bytes to receive. |


Source: `std/net.ml:967`

<a id="method-method-std-net-tcpconnection-sendall-function-sendall-data-std-net-ml-640793894"></a>
### sendAll

```ml
function sendAll(data)
```

Send the complete byte buffer or return an error.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `data` | `dynamic` | — | Bytes or UTF-8 text to send. |


Source: `std/net.ml:951`

<a id="method-method-std-net-tcpconnection-setkeepalive-function-setkeepalive-enabled-std-net-ml-376425303"></a>
### setKeepAlive

```ml
function setKeepAlive(enabled)
```

Enable or disable TCP keepalive.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `dynamic` | — | Whether keepalive is active. |


Source: `std/net.ml:995`

<a id="method-method-std-net-tcpconnection-setnodelay-function-setnodelay-enabled-std-net-ml-962907511"></a>
### setNoDelay

```ml
function setNoDelay(enabled)
```

Enable or disable Nagle's algorithm bypass.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | `dynamic` | — | Whether TCP_NODELAY is active. |


Source: `std/net.ml:988`

<a id="method-method-std-net-tcpconnection-setreceivetimeout-function-setreceivetimeout-milliseconds-std-net-ml-141272550"></a>
### setReceiveTimeout

```ml
function setReceiveTimeout(milliseconds)
```

Set the receive timeout in milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum wait time. |


Source: `std/net.ml:974`

<a id="method-method-std-net-tcpconnection-setsendtimeout-function-setsendtimeout-milliseconds-std-net-ml-978638174"></a>
### setSendTimeout

```ml
function setSendTimeout(milliseconds)
```

Set the send timeout in milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum wait time. |


Source: `std/net.ml:981`

<a id="method-method-std-net-tcpconnection-shutdown-function-shutdown-how-std-net-ml-120922612"></a>
### shutdown

```ml
function shutdown(how)
```

Shut down the selected connection direction.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `how` | `dynamic` | — | One of SD_RECEIVE, SD_SEND or SD_BOTH. |


Source: `std/net.ml:1002`
