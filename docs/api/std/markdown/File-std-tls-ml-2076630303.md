# `std/tls.ml`

[Home](README.md) · [Files](Files.md)

Provides the std tls package.

Package: [`std.tls`](Package-std-tls-1723050133.md)

Reachable from entry: **no**

## Imports

- `std/tls/_schannel.ml` as `native` → [std/tls/_schannel.ml](File-std-tls-schannel-ml-805501109.md)

## Declarations

<a id="function-function-std-tls-accept-function-accept-socket-options-std-tls-ml-800200611"></a>
### accept

```ml
function accept(socket, options)
```

Accept a native TLS server stream over an already-accepted std.net socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `socket` | `dynamic` | — | Value supplied for `socket`. |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:192`

<a id="function-function-std-tls-acceptserver-function-acceptserver-activeprovider-socket-options-std-tls-ml-616544682"></a>
### acceptServer

```ml
function acceptServer(activeProvider, socket, options)
```

Provide the accept server operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `activeProvider` | `dynamic` | — | Value supplied for `activeProvider`. |
| `socket` | `dynamic` | — | Value supplied for `socket`. |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:173`

<a id="function-function-std-tls-clientoptions-function-clientoptions-servername-std-tls-ml-739294414"></a>
### clientOptions

```ml
function clientOptions(serverName)
```

Provide the client options operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `serverName` | `dynamic` | — | Value supplied for `serverName`. |


Source: `std/tls.ml:87`

- [std.tls.ClientOptions](Type-std-tls-clientoptions-1357397796.md) — struct
<a id="function-function-std-tls-close-function-close-stream-std-tls-ml-845826000"></a>
### close

```ml
function close(stream)
```

Releases or resets close.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `stream` | `dynamic` | — | Value supplied for `stream`. |


Source: `std/tls.ml:241`

<a id="function-function-std-tls-connect-function-connect-socket-options-std-tls-ml-1752825555"></a>
### connect

```ml
function connect(socket, options)
```

Establish a native TLS client stream over an already-connected std.net socket.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `socket` | `dynamic` | — | Value supplied for `socket`. |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:185`

<a id="function-function-std-tls-connectclient-function-connectclient-activeprovider-socket-options-std-tls-ml-1045079724"></a>
### connectClient

```ml
function connectClient(activeProvider, socket, options)
```

Provide the connect client operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `activeProvider` | `dynamic` | — | Value supplied for `activeProvider`. |
| `socket` | `dynamic` | — | Value supplied for `socket`. |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:160`

<a id="function-function-std-tls-isstream-function-isstream-value-std-tls-ml-1952310795"></a>
### isStream

```ml
function isStream(value)
```

Reports whether is stream.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/tls.ml:198`

<a id="function-function-std-tls-nativeprovider-function-nativeprovider-std-tls-ml-1730938456"></a>
### nativeProvider

```ml
function nativeProvider()
```

Return the target-native provider: Schannel on Windows or OpenSSL 3 on Linux.


Source: `std/tls.ml:147`

<a id="function-function-std-tls-nativeprovidername-function-nativeprovidername-std-tls-ml-1534691896"></a>
### nativeProviderName

```ml
function nativeProviderName()
```

Provide the native provider name operation for this standard-library module.


Source: `std/tls.ml:152`

<a id="function-function-std-tls-pinnedclientoptions-function-pinnedclientoptions-servername-sha256pin-std-tls-ml-1120473458"></a>
### pinnedClientOptions

```ml
function pinnedClientOptions(serverName, sha256Pin)
```

Provide the pinned client options operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `serverName` | `dynamic` | — | Value supplied for `serverName`. |
| `sha256Pin` | `dynamic` | — | Value supplied for `sha256Pin`. |


Source: `std/tls.ml:94`

<a id="function-function-std-tls-provider-function-provider-name-openclient-openserver-sendbytes-receivebytes-shutdownstream-closestream-std-tls-ml-1543267410"></a>
### provider

```ml
function provider(name, openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream)
```

Provide the provider operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `dynamic` | — | Name of the requested item. |
| `openClient` | `dynamic` | — | Value supplied for `openClient`. |
| `openServer` | `dynamic` | — | Value supplied for `openServer`. |
| `sendBytes` | `dynamic` | — | Value supplied for `sendBytes`. |
| `receiveBytes` | `dynamic` | — | Value supplied for `receiveBytes`. |
| `shutdownStream` | `dynamic` | — | Value supplied for `shutdownStream`. |
| `closeStream` | `dynamic` | — | Value supplied for `closeStream`. |


Source: `std/tls.ml:137`

- [std.tls.Provider](Type-std-tls-provider-1415630088.md) — struct
<a id="function-function-std-tls-receive-function-receive-stream-maximumbytes-std-tls-ml-1474410327"></a>
### receive

```ml
function receive(stream, maximumBytes)
```

Provide the receive operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `stream` | `dynamic` | — | Value supplied for `stream`. |
| `maximumBytes` | `dynamic` | — | Value supplied for `maximumBytes`. |


Source: `std/tls.ml:223`

<a id="function-function-std-tls-sendall-function-sendall-stream-data-std-tls-ml-334269506"></a>
### sendAll

```ml
function sendAll(stream, data)
```

Provide the send all operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `stream` | `dynamic` | — | Value supplied for `stream`. |
| `data` | `dynamic` | — | Data to process. |


Source: `std/tls.ml:205`

<a id="function-function-std-tls-serveroptions-function-serveroptions-certificatereference-privatekeyreference-std-tls-ml-1841010559"></a>
### serverOptions

```ml
function serverOptions(certificateReference, privateKeyReference)
```

Provide the server options operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `certificateReference` | `dynamic` | — | Value supplied for `certificateReference`. |
| `privateKeyReference` | `dynamic` | — | Value supplied for `privateKeyReference`. |


Source: `std/tls.ml:101`

- [std.tls.ServerOptions](Type-std-tls-serveroptions-1817688456.md) — struct
<a id="function-function-std-tls-shutdown-function-shutdown-stream-std-tls-ml-1878438672"></a>
### shutdown

```ml
function shutdown(stream)
```

Provide the shutdown operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `stream` | `dynamic` | — | Value supplied for `stream`. |


Source: `std/tls.ml:234`

- [std.tls.Stream](Type-std-tls-stream-775546137.md) — struct
<a id="constant-constant-std-tls-tls-err-const-tls-err-267-std-tls-ml-486488596"></a>
### TLS_ERR

```ml
const TLS_ERR = 267
```

Track the tls err value used by this standard-library module.


Source: `std/tls.ml:21`

<a id="function-function-std-tls-validateclientoptions-function-validateclientoptions-options-std-tls-ml-702450042"></a>
### validateClientOptions

```ml
function validateClientOptions(options)
```

Provide the validate client options operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:107`

<a id="function-function-std-tls-validateserveroptions-function-validateserveroptions-options-std-tls-ml-787870250"></a>
### validateServerOptions

```ml
function validateServerOptions(options)
```

Provide the validate server options operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `options` | `dynamic` | — | Value supplied for `options`. |


Source: `std/tls.ml:120`
