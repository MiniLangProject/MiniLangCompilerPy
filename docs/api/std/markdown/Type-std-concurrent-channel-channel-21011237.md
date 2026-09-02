# `std.concurrent.channel.Channel`

[Home](README.md) · [Source file](File-std-concurrent-channel-ml-2137315633.md)

<a id="struct-struct-std-concurrent-channel-channel-struct-channel-std-concurrent-channel-ml-338364570"></a>
## Channel

```ml
struct Channel
```

Bounded multi-producer/multi-consumer FIFO. Waiting always happens outside the short queue lock, so a full producer cannot prevent a consumer from freeing space and close remains observable by blocked operations.


Source: `std/concurrent/channel.ml:145`

## Members

<a id="method-method-std-concurrent-channel-channel-close-function-close-std-concurrent-channel-ml-113930469"></a>
### close

```ml
function close()
```

Closes the channel to new sends.


Source: `std/concurrent/channel.ml:209`

<a id="method-method-std-concurrent-channel-channel-count-function-count-std-concurrent-channel-ml-1978801295"></a>
### Count

```ml
function Count()
```

Provide count behavior for this standard-library module.


Source: `std/concurrent/channel.ml:240`

<a id="method-method-std-concurrent-channel-channel-countvalue-function-countvalue-std-concurrent-channel-ml-423376045"></a>
### countValue

```ml
function countValue()
```

Provide count value behavior for this standard-library module.


Source: `std/concurrent/channel.ml:204`

<a id="method-method-std-concurrent-channel-channel-dispose-function-dispose-std-concurrent-channel-ml-894779547"></a>
### Dispose

```ml
function Dispose()
```

PascalCase Close is reserved by the native Thread API.


Source: `std/concurrent/channel.ml:242`

<a id="method-method-std-concurrent-channel-channel-dispose-function-dispose-std-concurrent-channel-ml-738798171"></a>
### dispose

```ml
function dispose()
```

Dispose only after every blocked caller has returned and the queue drained.


Source: `std/concurrent/channel.ml:215`

<a id="field-field-std-concurrent-channel-channel-disposed-disposed-std-concurrent-channel-ml-1766816297"></a>
### disposed

```ml
disposed
```

Disposed associated with `Channel`.


Source: `std/concurrent/channel.ml:149`

<a id="static_method-static-method-std-concurrent-channel-channel-new-static-function-new-capacity-std-concurrent-channel-ml-477572384"></a>
### new

```ml
static function new(capacity)
```

Creates a channel with bounded capacity.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `capacity` | `dynamic` | — | Value supplied for `capacity`. |


Source: `std/concurrent/channel.ml:153`

<a id="field-field-std-concurrent-channel-channel-queue-queue-std-concurrent-channel-ml-878553291"></a>
### queue

```ml
queue
```

Queue associated with `Channel`.


Source: `std/concurrent/channel.ml:147`

<a id="method-method-std-concurrent-channel-channel-receive-function-receive-std-concurrent-channel-ml-234908883"></a>
### Receive

```ml
function Receive()
```

Exposes blocking receive through a PascalCase alias.


Source: `std/concurrent/channel.ml:233`

<a id="method-method-std-concurrent-channel-channel-receive-function-receive-std-concurrent-channel-ml-1619698643"></a>
### receive

```ml
function receive()
```

Receives the next channel value, waiting when necessary.


Source: `std/concurrent/channel.ml:200`

<a id="method-method-std-concurrent-channel-channel-receivefor-function-receivefor-milliseconds-std-concurrent-channel-ml-141724103"></a>
### ReceiveFor

```ml
function ReceiveFor(milliseconds)
```

Exposes timed receive through a PascalCase alias.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/channel.ml:236`

<a id="method-method-std-concurrent-channel-channel-receivefor-function-receivefor-milliseconds-std-concurrent-channel-ml-983386375"></a>
### receiveFor

```ml
function receiveFor(milliseconds)
```

Waits up to a bounded duration to receive a channel value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/channel.ml:185`

<a id="method-method-std-concurrent-channel-channel-send-function-send-value-std-concurrent-channel-ml-867878686"></a>
### Send

```ml
function Send(value)
```

Provide send behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:224`

<a id="method-method-std-concurrent-channel-channel-send-function-send-value-std-concurrent-channel-ml-1435514270"></a>
### send

```ml
function send(value)
```

Provide send behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:178`

<a id="method-method-std-concurrent-channel-channel-sendfor-function-sendfor-value-milliseconds-std-concurrent-channel-ml-564623202"></a>
### SendFor

```ml
function SendFor(value, milliseconds)
```

Provide send for behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/channel.ml:228`

<a id="method-method-std-concurrent-channel-channel-sendfor-function-sendfor-value-milliseconds-std-concurrent-channel-ml-388594722"></a>
### sendFor

```ml
function sendFor(value, milliseconds)
```

Provide send for behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |
| `milliseconds` | `dynamic` | — | Maximum duration in milliseconds. |


Source: `std/concurrent/channel.ml:163`

<a id="method-method-std-concurrent-channel-channel-tryreceive-function-tryreceive-std-concurrent-channel-ml-1599168617"></a>
### TryReceive

```ml
function TryReceive()
```

Provide try receive behavior for this standard-library module.


Source: `std/concurrent/channel.ml:238`

<a id="method-method-std-concurrent-channel-channel-tryreceive-function-tryreceive-std-concurrent-channel-ml-2005260969"></a>
### tryReceive

```ml
function tryReceive()
```

Provide try receive behavior for this standard-library module.


Source: `std/concurrent/channel.ml:202`

<a id="method-method-std-concurrent-channel-channel-trysend-function-trysend-value-std-concurrent-channel-ml-121058408"></a>
### TrySend

```ml
function TrySend(value)
```

Provide try send behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:231`

<a id="method-method-std-concurrent-channel-channel-trysend-function-trysend-value-std-concurrent-channel-ml-416491496"></a>
### trySend

```ml
function trySend(value)
```

Provide try send behavior for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Value to process. |


Source: `std/concurrent/channel.ml:181`
