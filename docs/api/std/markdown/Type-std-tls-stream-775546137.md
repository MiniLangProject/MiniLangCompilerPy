# `std.tls.Stream`

[Home](README.md) · [Source file](File-std-tls-ml-2076630303.md)

<a id="struct-struct-std-tls-stream-struct-stream-std-tls-ml-1685820173"></a>
## Stream

```ml
struct Stream
```

Represents stream.


Source: `std/tls.ml:70`

## Members

<a id="method-method-std-tls-stream-close-function-close-std-tls-ml-1823044671"></a>
### close

```ml
function close()
```

Release TLS state without closing the underlying TCP socket.


Source: `std/tls.ml:98`

<a id="field-field-std-tls-stream-closed-closed-std-tls-ml-883062905"></a>
### closed

```ml
closed
```

Closed associated with `Stream`.


Source: `std/tls.ml:78`

<a id="method-method-std-tls-stream-isclosed-function-isclosed-std-tls-ml-1435791159"></a>
### isClosed

```ml
function isClosed()
```

Report whether this TLS state has been closed.


Source: `std/tls.ml:103`

<a id="field-field-std-tls-stream-provider-provider-std-tls-ml-1222590419"></a>
### provider

```ml
provider
```

Provider associated with `Stream`.


Source: `std/tls.ml:72`

<a id="method-method-std-tls-stream-receive-function-receive-maximumbytes-std-tls-ml-1572700364"></a>
### receive

```ml
function receive(maximumBytes)
```

Receive up to the requested number of bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `maximumBytes` | `dynamic` | — | Maximum payload size. |


Source: `std/tls.ml:88`

<a id="method-method-std-tls-stream-sendall-function-sendall-data-std-tls-ml-310327501"></a>
### sendAll

```ml
function sendAll(data)
```

Send all bytes, including partially accepted provider writes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `data` | `dynamic` | — | Bytes to send. |


Source: `std/tls.ml:82`

<a id="field-field-std-tls-stream-serverside-serverside-std-tls-ml-873928809"></a>
### serverSide

```ml
serverSide
```

Server side associated with `Stream`.


Source: `std/tls.ml:76`

<a id="method-method-std-tls-stream-shutdown-function-shutdown-std-tls-ml-1156232355"></a>
### shutdown

```ml
function shutdown()
```

Send a TLS shutdown notification when supported by the provider.


Source: `std/tls.ml:93`

<a id="field-field-std-tls-stream-state-state-std-tls-ml-427289269"></a>
### state

```ml
state
```

State associated with `Stream`.


Source: `std/tls.ml:74`
