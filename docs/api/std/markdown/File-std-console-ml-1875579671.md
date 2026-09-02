# `std/console.ml`

[Home](README.md) · [Files](Files.md)

Provides the std console package.

Package: [`std.console`](Package-std-console-1345532205.md)

Reachable from entry: **no**

## Declarations

<a id="constant-constant-std-console-console-err-const-console-err-262-std-console-ml-1530297937"></a>
### CONSOLE_ERR

```ml
const CONSOLE_ERR = 262
```

Track the console err value used by this standard-library module.


Source: `std/console.ml:15`

<a id="constant-constant-std-console-cp-utf8-const-cp-utf8-65001-std-console-ml-623535779"></a>
### CP_UTF8

```ml
const CP_UTF8 = 65001
```

Track the cp utf8 value used by this standard-library module.


Source: `std/console.ml:27`

<a id="function-function-std-console-disablequickedit-function-disablequickedit-std-console-ml-1305818672"></a>
### disableQuickEdit

```ml
function disableQuickEdit()
```

Prevent Windows QuickEdit from suspending a server process. Other targets have no equivalent mode and report success without changing terminal state.


Source: `std/console.ml:109`

<a id="constant-constant-std-console-enable-echo-input-const-enable-echo-input-4-std-console-ml-1340769603"></a>
### ENABLE_ECHO_INPUT

```ml
const ENABLE_ECHO_INPUT = 4
```

Track the enable echo input value used by this standard-library module.


Source: `std/console.ml:21`

<a id="constant-constant-std-console-enable-extended-flags-const-enable-extended-flags-128-std-console-ml-133487328"></a>
### ENABLE_EXTENDED_FLAGS

```ml
const ENABLE_EXTENDED_FLAGS = 128
```

Track the enable extended flags value used by this standard-library module.


Source: `std/console.ml:25`

<a id="constant-constant-std-console-enable-quick-edit-mode-const-enable-quick-edit-mode-64-std-console-ml-1189238277"></a>
### ENABLE_QUICK_EDIT_MODE

```ml
const ENABLE_QUICK_EDIT_MODE = 64
```

Track the enable quick edit mode value used by this standard-library module.


Source: `std/console.ml:23`

<a id="function-function-std-console-isinteractive-function-isinteractive-std-console-ml-470243024"></a>
### isInteractive

```ml
function isInteractive()
```

Reports whether is interactive.


Source: `std/console.ml:97`

<a id="constant-constant-std-console-max-secret-utf16-units-const-max-secret-utf16-units-4096-std-console-ml-517793938"></a>
### MAX_SECRET_UTF16_UNITS

```ml
const MAX_SECRET_UTF16_UNITS = 4096
```

Track the max secret utf16 units value used by this standard-library module.


Source: `std/console.ml:31`

<a id="function-function-std-console-readpassword-function-readpassword-prompt-std-console-ml-1668045086"></a>
### readPassword

```ml
function readPassword(prompt)
```

Returns read password.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `prompt` | `dynamic` | — | Value supplied for `prompt`. |


Source: `std/console.ml:181`

<a id="function-function-std-console-readsecret-function-readsecret-prompt-maximumbytes-std-console-ml-989090479"></a>
### readSecret

```ml
function readSecret(prompt, maximumBytes)
```

Returns read secret.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `prompt` | `dynamic` | — | Value supplied for `prompt`. |
| `maximumBytes` | `dynamic` | — | Value supplied for `maximumBytes`. |


Source: `std/console.ml:125`

<a id="function-function-std-console-readsecretconfirmed-function-readsecretconfirmed-prompt-confirmationprompt-maximumbytes-std-console-ml-500058034"></a>
### readSecretConfirmed

```ml
function readSecretConfirmed(prompt, confirmationPrompt, maximumBytes)
```

Returns read secret confirmed.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `prompt` | `dynamic` | — | Value supplied for `prompt`. |
| `confirmationPrompt` | `dynamic` | — | Value supplied for `confirmationPrompt`. |
| `maximumBytes` | `dynamic` | — | Value supplied for `maximumBytes`. |


Source: `std/console.ml:189`

<a id="constant-constant-std-console-std-input-handle-const-std-input-handle-10-std-console-ml-1383706861"></a>
### STD_INPUT_HANDLE

```ml
const STD_INPUT_HANDLE = -10
```

Track the std input handle value used by this standard-library module.


Source: `std/console.ml:17`

<a id="constant-constant-std-console-std-output-handle-const-std-output-handle-11-std-console-ml-1146836344"></a>
### STD_OUTPUT_HANDLE

```ml
const STD_OUTPUT_HANDLE = -11
```

Track the std output handle value used by this standard-library module.


Source: `std/console.ml:19`

<a id="constant-constant-std-console-wc-err-invalid-chars-const-wc-err-invalid-chars-128-std-console-ml-888982478"></a>
### WC_ERR_INVALID_CHARS

```ml
const WC_ERR_INVALID_CHARS = 128
```

Track the wc err invalid chars value used by this standard-library module.


Source: `std/console.ml:29`

<a id="function-function-std-console-wipe-function-wipe-buffer-std-console-ml-1632003642"></a>
### wipe

```ml
function wipe(buffer)
```

Provide the wipe operation for this standard-library module.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |


Source: `std/console.ml:53`
