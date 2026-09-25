/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Portable native media playback. The small platform bridge owns decoder
// threads and native resources; MiniLang observes its bounded event queue.
//! Provides native audio/video playback on Windows and Linux.

package std.video

/// Stable std.video error number.
const VIDEO_ERROR = 1781
/// Native bridge ABI expected by this version of the standard library.
const VIDEO_ABI_VERSION = 1
/// Largest seek value that remains representable as GStreamer nanoseconds.
const MAX_VIDEO_MILLISECONDS = 9223372036854

/// Player lifecycle states.
enum State
  Empty = 0
  Loading = 1
  Ready = 2
  Playing = 3
  Paused = 4
  Stopped = 5
  Buffering = 6
  Ended = 7
  Failed = 8
  Closed = 9
end enum

/// Events delivered by Player.pollEvent().
enum EventKind
  Ready = 1
  Playing = 2
  Paused = 3
  Stopped = 4
  Buffering = 5
  Ended = 6
  FormatChanged = 7
  Error = 8
end enum

/// Options applied when a player is opened.
struct PlayerOptions
  /// Permit non-file media URIs.
  allowNetwork
  /// Restart automatically after end of stream.
  loopEnabled
  /// Linear volume in the inclusive range 0.0 through 1.0.
  volume
  /// Start with audio muted.
  muted
  /// Initial playback rate.
  playbackRate

  /// Return conservative defaults: local input, no loop, full volume.
  static function defaults()
    return std.video.PlayerOptions(false, false, 1.0, false, 1.0)
  end function
end struct

/// One asynchronous player notification.
struct Event
  /// Event category.
  kind
  /// Player state observed after the event.
  state
  /// Backend-specific numeric diagnostic, or zero.
  code
  /// Human-readable detail, empty for ordinary state changes.
  message
end struct

#if TARGET_OS == "windows"
/// Native bridge ABI query.
/// @internal
extern function _videoAbiVersion() from "minilang_video.dll" symbol "mlv_abi_version" returns u32
/// Native bridge backend-name query.
/// @internal
extern function _videoBackend(message as bytes, capacity as int) from "minilang_video.dll" symbol "mlv_backend" returns int
/// Native bridge open operation.
/// @internal
extern function _videoOpen(source as cstr, windowHandle as ptr, allowNetwork as int) from "minilang_video.dll" symbol "mlv_open" returns ptr
/// Native bridge output-target operation.
/// @internal
extern function _videoAttach(handle as ptr, windowHandle as ptr) from "minilang_video.dll" symbol "mlv_attach" returns int
/// Native bridge playback operation.
/// @internal
extern function _videoPlay(handle as ptr) from "minilang_video.dll" symbol "mlv_play" returns int
/// Native bridge pause operation.
/// @internal
extern function _videoPause(handle as ptr) from "minilang_video.dll" symbol "mlv_pause" returns int
/// Native bridge stop operation.
/// @internal
extern function _videoStop(handle as ptr) from "minilang_video.dll" symbol "mlv_stop" returns int
/// Native bridge seek operation.
/// @internal
extern function _videoSeek(handle as ptr, milliseconds as i64) from "minilang_video.dll" symbol "mlv_seek" returns int
/// Native bridge volume operation.
/// @internal
extern function _videoSetVolume(handle as ptr, volume as double) from "minilang_video.dll" symbol "mlv_set_volume" returns int
/// Native bridge mute operation.
/// @internal
extern function _videoSetMuted(handle as ptr, muted as int) from "minilang_video.dll" symbol "mlv_set_muted" returns int
/// Native bridge playback-rate operation.
/// @internal
extern function _videoSetRate(handle as ptr, rate as double) from "minilang_video.dll" symbol "mlv_set_rate" returns int
/// Native bridge loop operation.
/// @internal
extern function _videoSetLoop(handle as ptr, enabled as int) from "minilang_video.dll" symbol "mlv_set_loop" returns int
/// Native bridge state query.
/// @internal
extern function _videoState(handle as ptr) from "minilang_video.dll" symbol "mlv_state" returns int
/// Native bridge position query.
/// @internal
extern function _videoPosition(handle as ptr) from "minilang_video.dll" symbol "mlv_position_ms" returns i64
/// Native bridge duration query.
/// @internal
extern function _videoDuration(handle as ptr) from "minilang_video.dll" symbol "mlv_duration_ms" returns i64
/// Native bridge audio-stream query.
/// @internal
extern function _videoHasAudio(handle as ptr) from "minilang_video.dll" symbol "mlv_has_audio" returns int
/// Native bridge video-stream query.
/// @internal
extern function _videoHasVideo(handle as ptr) from "minilang_video.dll" symbol "mlv_has_video" returns int
/// Native bridge width query.
/// @internal
extern function _videoWidth(handle as ptr) from "minilang_video.dll" symbol "mlv_video_width" returns int
/// Native bridge height query.
/// @internal
extern function _videoHeight(handle as ptr) from "minilang_video.dll" symbol "mlv_video_height" returns int
/// Native bridge event dequeue operation.
/// @internal
extern function _videoPollEvent(handle as ptr, message as bytes, capacity as int) from "minilang_video.dll" symbol "mlv_poll_event" returns int
/// Native bridge event-code query.
/// @internal
extern function _videoEventCode(handle as ptr) from "minilang_video.dll" symbol "mlv_event_code" returns int
/// Native bridge diagnostic query.
/// @internal
extern function _videoError(handle as ptr, message as bytes, capacity as int) from "minilang_video.dll" symbol "mlv_error" returns int
/// Native bridge cleanup operation.
/// @internal
extern function _videoClose(handle as ptr) from "minilang_video.dll" symbol "mlv_close" returns void
#else
/// Native bridge ABI query.
/// @internal
extern function _videoAbiVersion() from "$ORIGIN/libminilang_video.so" symbol "mlv_abi_version" returns u32
/// Native bridge backend-name query.
/// @internal
extern function _videoBackend(message as bytes, capacity as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_backend" returns int
/// Native bridge open operation.
/// @internal
extern function _videoOpen(source as cstr, windowHandle as ptr, allowNetwork as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_open" returns ptr
/// Native bridge output-target operation.
/// @internal
extern function _videoAttach(handle as ptr, windowHandle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_attach" returns int
/// Native bridge playback operation.
/// @internal
extern function _videoPlay(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_play" returns int
/// Native bridge pause operation.
/// @internal
extern function _videoPause(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_pause" returns int
/// Native bridge stop operation.
/// @internal
extern function _videoStop(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_stop" returns int
/// Native bridge seek operation.
/// @internal
extern function _videoSeek(handle as ptr, milliseconds as i64) from "$ORIGIN/libminilang_video.so" symbol "mlv_seek" returns int
/// Native bridge volume operation.
/// @internal
extern function _videoSetVolume(handle as ptr, volume as double) from "$ORIGIN/libminilang_video.so" symbol "mlv_set_volume" returns int
/// Native bridge mute operation.
/// @internal
extern function _videoSetMuted(handle as ptr, muted as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_set_muted" returns int
/// Native bridge playback-rate operation.
/// @internal
extern function _videoSetRate(handle as ptr, rate as double) from "$ORIGIN/libminilang_video.so" symbol "mlv_set_rate" returns int
/// Native bridge loop operation.
/// @internal
extern function _videoSetLoop(handle as ptr, enabled as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_set_loop" returns int
/// Native bridge state query.
/// @internal
extern function _videoState(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_state" returns int
/// Native bridge position query.
/// @internal
extern function _videoPosition(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_position_ms" returns i64
/// Native bridge duration query.
/// @internal
extern function _videoDuration(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_duration_ms" returns i64
/// Native bridge audio-stream query.
/// @internal
extern function _videoHasAudio(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_has_audio" returns int
/// Native bridge video-stream query.
/// @internal
extern function _videoHasVideo(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_has_video" returns int
/// Native bridge width query.
/// @internal
extern function _videoWidth(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_video_width" returns int
/// Native bridge height query.
/// @internal
extern function _videoHeight(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_video_height" returns int
/// Native bridge event dequeue operation.
/// @internal
extern function _videoPollEvent(handle as ptr, message as bytes, capacity as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_poll_event" returns int
/// Native bridge event-code query.
/// @internal
extern function _videoEventCode(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_event_code" returns int
/// Native bridge diagnostic query.
/// @internal
extern function _videoError(handle as ptr, message as bytes, capacity as int) from "$ORIGIN/libminilang_video.so" symbol "mlv_error" returns int
/// Native bridge cleanup operation.
/// @internal
extern function _videoClose(handle as ptr) from "$ORIGIN/libminilang_video.so" symbol "mlv_close" returns void
#endif

/// Return an std.video error with backend context.
/// @internal
function _error(message)
  return error(VIDEO_ERROR, message)
end function

/// Map a bridge integer to the public state enum.
/// @internal
function _state(value)
  if value == 1 then return State.Loading end if
  if value == 2 then return State.Ready end if
  if value == 3 then return State.Playing end if
  if value == 4 then return State.Paused end if
  if value == 5 then return State.Stopped end if
  if value == 6 then return State.Buffering end if
  if value == 7 then return State.Ended end if
  if value == 8 then return State.Failed end if
  if value == 9 then return State.Closed end if
  return State.Empty
end function

/// Map a bridge integer to the public event enum.
/// @internal
function _eventKind(value)
  if value == 2 then return EventKind.Playing end if
  if value == 3 then return EventKind.Paused end if
  if value == 4 then return EventKind.Stopped end if
  if value == 5 then return EventKind.Buffering end if
  if value == 6 then return EventKind.Ended end if
  if value == 7 then return EventKind.FormatChanged end if
  if value == 8 then return EventKind.Error end if
  return EventKind.Ready
end function

/// Validate player options before native resources are allocated.
/// @internal
function _validateOptions(options)
  if options is not PlayerOptions then return _error("options must be PlayerOptions") end if
  if typeof(options.allowNetwork) != "bool" then return _error("allowNetwork must be bool") end if
  if typeof(options.loopEnabled) != "bool" then return _error("loopEnabled must be bool") end if
  if typeof(options.muted) != "bool" then return _error("muted must be bool") end if
  if typeof(options.volume) != "int" and typeof(options.volume) != "float" then return _error("volume must be numeric") end if
  if options.volume != options.volume or options.volume < 0 or options.volume > 1 then return _error("volume must be between 0 and 1") end if
  if typeof(options.playbackRate) != "int" and typeof(options.playbackRate) != "float" then return _error("playbackRate must be numeric") end if
  if options.playbackRate != options.playbackRate or options.playbackRate < 0.25 or options.playbackRate > 4.0 then return _error("playbackRate must be between 0.25 and 4.0") end if
  return true
end function

/// A native player handle with deterministic explicit ownership.
struct Player
  /// Opaque bridge handle.
  /// @internal
  handle
  /// Options retained for introspection.
  options
  /// Reusable event text buffer.
  /// @internal
  eventBuffer
  /// Whether close() has released the native handle.
  /// @internal
  closed

  /// Open a local path or URI without beginning playback.
  /// Attach a native child-window handle before play() when video is visible.
  /// @param source Local filename, file URI, or explicitly enabled network URI.
  /// @param options PlayerOptions, or void for defaults.
  static function open(source, options = void)
    if typeof(source) != "string" or len(source) == 0 then return _error("source must be a non-empty string") end if
    actual = options
    if actual is void then actual = PlayerOptions.defaults() end if
    valid = _validateOptions(actual)
    if typeof(valid) == "error" then return valid end if
    if _videoAbiVersion() != VIDEO_ABI_VERSION then return _error("native video bridge ABI mismatch") end if

    allowNetwork = 0
    if actual.allowNetwork then allowNetwork = 1 end if
    handle = _videoOpen(source, 0, allowNetwork)
    if handle == 0 then
      messageBuffer = bytes(512, 0)
      _videoError(0, messageBuffer, len(messageBuffer))
      detail = decodeZ(messageBuffer)
      if detail is void or detail == "" then detail = "native backend could not open the source" end if
      return _error(detail)
    end if

    retained = PlayerOptions(actual.allowNetwork, actual.loopEnabled, actual.volume, actual.muted, actual.playbackRate)
    player = std.video.Player(handle, retained, bytes(512, 0), false)
    configured = try(player.setLoop(actual.loopEnabled))
    if typeof(configured) == "error" then player.close(); return configured end if
    configured = try(player.setVolume(actual.volume))
    if typeof(configured) == "error" then player.close(); return configured end if
    configured = try(player.setMuted(actual.muted))
    if typeof(configured) == "error" then player.close(); return configured end if
    configured = try(player.setPlaybackRate(actual.playbackRate))
    if typeof(configured) == "error" then player.close(); return configured end if
    return player
  end function

  /// Return the backend selected for this target.
  function backend()
    if this.closed then return "" end if
    return std.video.backend()
  end function

  /// Attach video output to a native child-window handle before playback.
  /// @param windowHandle Non-zero platform handle owned by the GUI.
  function attach(windowHandle)
    if this.closed then return _error("player is closed") end if
    if typeof(windowHandle) != "int" or windowHandle == 0 then return _error("window handle must be a non-zero int") end if
    if _videoAttach(this.handle, windowHandle) == 0 then return this._lastError("attach") end if
    return true
  end function

  /// Start or resume playback.
  function play()
    if this.closed then return _error("player is closed") end if
    if _videoPlay(this.handle) == 0 then return this._lastError("play") end if
    return true
  end function

  /// Pause playback while retaining the current position.
  function pause()
    if this.closed then return _error("player is closed") end if
    if _videoPause(this.handle) == 0 then return this._lastError("pause") end if
    return true
  end function

  /// Stop playback and seek to the beginning.
  function stop()
    if this.closed then return _error("player is closed") end if
    if _videoStop(this.handle) == 0 then return this._lastError("stop") end if
    return true
  end function

  /// Seek to a non-negative millisecond position.
  /// @param milliseconds Target position from the beginning of the stream.
  function seek(milliseconds)
    if this.closed then return _error("player is closed") end if
    if typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_VIDEO_MILLISECONDS then
      return _error("seek position is outside the supported millisecond range")
    end if
    if _videoSeek(this.handle, milliseconds) == 0 then return this._lastError("seek") end if
    return true
  end function

  /// Return the current playback position in milliseconds.
  function position()
    if this.closed then return 0 end if
    return _videoPosition(this.handle)
  end function

  /// Return duration in milliseconds, or -1 while unknown.
  function duration()
    if this.closed then return -1 end if
    return _videoDuration(this.handle)
  end function

  /// Return the current lifecycle state.
  function state()
    if this.closed then return State.Closed end if
    return _state(_videoState(this.handle))
  end function

  /// Set linear volume from 0.0 through 1.0.
  /// @param volume Linear volume in the inclusive range 0.0 through 1.0.
  function setVolume(volume)
    if this.closed then return _error("player is closed") end if
    if (typeof(volume) != "int" and typeof(volume) != "float") or volume != volume or volume < 0 or volume > 1 then
      return _error("volume must be between 0 and 1")
    end if
    if _videoSetVolume(this.handle, volume) == 0 then return this._lastError("setVolume") end if
    this.options.volume = volume
    return true
  end function

  /// Mute or unmute audio.
  /// @param muted Whether audio output is muted.
  function setMuted(muted)
    if this.closed then return _error("player is closed") end if
    if typeof(muted) != "bool" then return _error("muted must be bool") end if
    value = 0
    if muted then value = 1 end if
    if _videoSetMuted(this.handle, value) == 0 then return this._lastError("setMuted") end if
    this.options.muted = muted
    return true
  end function

  /// Set playback speed from 0.25 through 4.0.
  /// @param rate Requested playback-rate multiplier.
  function setPlaybackRate(rate)
    if this.closed then return _error("player is closed") end if
    if (typeof(rate) != "int" and typeof(rate) != "float") or rate != rate or rate < 0.25 or rate > 4.0 then
      return _error("playback rate must be between 0.25 and 4.0")
    end if
    if _videoSetRate(this.handle, rate) == 0 then return this._lastError("setPlaybackRate") end if
    this.options.playbackRate = rate
    return true
  end function

  /// Enable or disable automatic restart after end of stream.
  /// @param enabled Whether end-of-stream restarts playback.
  function setLoop(enabled)
    if this.closed then return _error("player is closed") end if
    if typeof(enabled) != "bool" then return _error("loop must be bool") end if
    value = 0
    if enabled then value = 1 end if
    if _videoSetLoop(this.handle, value) == 0 then return this._lastError("setLoop") end if
    this.options.loopEnabled = enabled
    return true
  end function

  /// Report whether the loaded source has an audio stream.
  function hasAudio()
    if this.closed then return false end if
    return _videoHasAudio(this.handle) != 0
  end function

  /// Report whether the loaded source has a video stream.
  function hasVideo()
    if this.closed then return false end if
    return _videoHasVideo(this.handle) != 0
  end function

  /// Return the decoded video width, or zero before metadata is available.
  function videoWidth()
    if this.closed then return 0 end if
    return _videoWidth(this.handle)
  end function

  /// Return the decoded video height, or zero before metadata is available.
  function videoHeight()
    if this.closed then return 0 end if
    return _videoHeight(this.handle)
  end function

  /// Return the next queued event, or void when no event is available.
  function pollEvent()
    if this.closed then return end if
    fillBytes(this.eventBuffer, 0, len(this.eventBuffer), 0)
    kind = _videoPollEvent(this.handle, this.eventBuffer, len(this.eventBuffer))
    if kind == 0 then return end if
    message = decodeZ(this.eventBuffer)
    if message is void then message = "" end if
    return std.video.Event(_eventKind(kind), this.state(), _videoEventCode(this.handle), message)
  end function

  /// Release playback threads, decoder state and native handles.
  /// Multiple close calls are harmless.
  function close()
    if this.closed then return true end if
    handle = this.handle
    this.handle = 0
    this.closed = true
    _videoClose(handle)
    return true
  end function

  /// Convert the bridge's last diagnostic to an std.video error.
  /// @internal
  function _lastError(operation)
    fillBytes(this.eventBuffer, 0, len(this.eventBuffer), 0)
    _videoError(this.handle, this.eventBuffer, len(this.eventBuffer))
    detail = decodeZ(this.eventBuffer)
    if detail is void or detail == "" then detail = "native operation failed" end if
    return _error(operation + ": " + detail)
  end function
end struct

/// Return the native backend name.
function backend()
  messageBuffer = bytes(64, 0)
  _videoBackend(messageBuffer, len(messageBuffer))
  name = decodeZ(messageBuffer)
  if name is void then return "" end if
  return name
end function

/// Report whether the installed bridge ABI matches this standard library.
function isAvailable()
  return _videoAbiVersion() == VIDEO_ABI_VERSION
end function
