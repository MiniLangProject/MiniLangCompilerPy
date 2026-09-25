/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Portable native audio playback built on the shared media bridge.
//! Provides WAV, MP3 and MIDI playback on Windows and Linux.

package std.audio

import std.path as path
import std.string as strings
import std.video as media

/// Stable std.audio error number.
const AUDIO_ERROR = 1782
/// Largest supported seek position in milliseconds.
const MAX_AUDIO_MILLISECONDS = media.MAX_VIDEO_MILLISECONDS

/// Audio formats recognized from a source filename.
enum Format
  Unknown = 0
  Wave = 1
  Mp3 = 2
  Midi = 3
end enum

/// Audio-player lifecycle states.
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

/// Options applied when an audio player is opened.
struct PlayerOptions
  /// Permit non-file audio URIs.
  allowNetwork
  /// Restart automatically after end of stream.
  loopEnabled
  /// Linear volume in the inclusive range 0.0 through 1.0.
  volume
  /// Start with audio muted.
  muted
  /// Initial playback-rate multiplier.
  playbackRate

  /// Return conservative defaults: local input, no loop and full volume.
  static function defaults()
    return std.audio.PlayerOptions(false, false, 1.0, false, 1.0)
  end function
end struct

/// One asynchronous audio-player notification.
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

/// Return an std.audio error.
/// @internal
function _error(message)
  return error(AUDIO_ERROR, message)
end function

/// Validate options before opening the shared media backend.
/// @internal
function _validateOptions(options)
  if options is not PlayerOptions then return _error("options must be PlayerOptions") end if
  if typeof(options.allowNetwork) != "bool" then return _error("allowNetwork must be bool") end if
  if typeof(options.loopEnabled) != "bool" then return _error("loopEnabled must be bool") end if
  if typeof(options.muted) != "bool" then return _error("muted must be bool") end if
  if typeof(options.volume) != "int" and typeof(options.volume) != "float" then
    return _error("volume must be numeric")
  end if
  if options.volume != options.volume or options.volume < 0 or options.volume > 1 then
    return _error("volume must be between 0 and 1")
  end if
  if typeof(options.playbackRate) != "int" and typeof(options.playbackRate) != "float" then
    return _error("playbackRate must be numeric")
  end if
  if options.playbackRate != options.playbackRate or options.playbackRate < 0.25 or options.playbackRate > 4.0 then
    return _error("playbackRate must be between 0.25 and 4.0")
  end if
  return true
end function

/// Convert a shared-media state into an audio state.
/// @internal
function _state(value)
  if value == media.State.Loading then return State.Loading end if
  if value == media.State.Ready then return State.Ready end if
  if value == media.State.Playing then return State.Playing end if
  if value == media.State.Paused then return State.Paused end if
  if value == media.State.Stopped then return State.Stopped end if
  if value == media.State.Buffering then return State.Buffering end if
  if value == media.State.Ended then return State.Ended end if
  if value == media.State.Failed then return State.Failed end if
  if value == media.State.Closed then return State.Closed end if
  return State.Empty
end function

/// Convert a shared-media event into an audio event category.
/// @internal
function _eventKind(value)
  if value == media.EventKind.Playing then return EventKind.Playing end if
  if value == media.EventKind.Paused then return EventKind.Paused end if
  if value == media.EventKind.Stopped then return EventKind.Stopped end if
  if value == media.EventKind.Buffering then return EventKind.Buffering end if
  if value == media.EventKind.Ended then return EventKind.Ended end if
  if value == media.EventKind.FormatChanged then return EventKind.FormatChanged end if
  if value == media.EventKind.Error then return EventKind.Error end if
  return EventKind.Ready
end function

/// Detect a supported audio format from a local path or URI suffix.
/// Unknown extensions remain playable when the native backend supports them.
/// @param source Source path or URI.
function formatFromSource(source)
  if typeof(source) != "string" then return Format.Unknown end if
  pathSource = source
  query = strings.indexOf(pathSource, "?", 0)
  fragment = strings.indexOf(pathSource, "#", 0)
  cutoff = len(pathSource)
  if query >= 0 and query < cutoff then cutoff = query end if
  if fragment >= 0 and fragment < cutoff then cutoff = fragment end if
  if cutoff < len(pathSource) then pathSource = strings.substr(pathSource, 0, cutoff) end if
  extension = strings.toLowerAscii(path.extension(pathSource))
  if extension == ".wav" or extension == ".wave" then return Format.Wave end if
  if extension == ".mp3" then return Format.Mp3 end if
  if extension == ".mid" or extension == ".midi" then return Format.Midi end if
  return Format.Unknown
end function

/// Return a stable lowercase name for an audio format.
/// @param value Format enum value.
function formatName(value)
  if value == Format.Wave then return "wave" end if
  if value == Format.Mp3 then return "mp3" end if
  if value == Format.Midi then return "midi" end if
  return "unknown"
end function

/// Report whether a format is part of std.audio's portable format contract.
/// @param value Format enum value.
function isSupportedFormat(value)
  return value == Format.Wave or value == Format.Mp3 or value == Format.Midi
end function

/// A native audio player with deterministic explicit ownership.
struct Player
  /// Shared native media player.
  /// @internal
  mediaPlayer
  /// Options retained for introspection.
  options
  /// Format inferred from the source name.
  /// @internal
  sourceFormat
  /// Whether close() has released the shared media player.
  /// @internal
  closed

  /// Open a local audio path or URI without beginning playback.
  /// WAV, MP3 and MIDI are the portable named formats.
  /// @param source Local filename, file URI, or explicitly enabled network URI.
  /// @param options PlayerOptions, or void for defaults.
  static function open(source, options = void)
    if typeof(source) != "string" or len(source) == 0 then
      return _error("source must be a non-empty string")
    end if

    actual = options
    if actual is void then actual = PlayerOptions.defaults() end if
    valid = _validateOptions(actual)
    if typeof(valid) == "error" then return valid end if
    if not media.isAvailable() then return _error("native media bridge ABI mismatch") end if

    sharedOptions = media.PlayerOptions(
      actual.allowNetwork,
      actual.loopEnabled,
      actual.volume,
      actual.muted,
      actual.playbackRate)
    shared = try(media.Player.open(source, sharedOptions))
    if typeof(shared) == "error" then return _error(shared.message) end if

    retained = PlayerOptions(
      actual.allowNetwork,
      actual.loopEnabled,
      actual.volume,
      actual.muted,
      actual.playbackRate)
    return std.audio.Player(shared, retained, formatFromSource(source), false)
  end function

  /// Return the native backend selected for this target.
  function backend()
    if this.closed then return "" end if
    return this.mediaPlayer.backend()
  end function

  /// Return the format inferred from the source filename.
  function format()
    return this.sourceFormat
  end function

  /// Start or resume playback.
  function play()
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.play())
    if typeof(result) == "error" then return _error(result.message) end if
    return true
  end function

  /// Pause playback while retaining the current position.
  function pause()
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.pause())
    if typeof(result) == "error" then return _error(result.message) end if
    return true
  end function

  /// Stop playback and seek to the beginning.
  function stop()
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.stop())
    if typeof(result) == "error" then return _error(result.message) end if
    return true
  end function

  /// Seek to a non-negative millisecond position.
  /// Backend support for MIDI seeking depends on the installed synthesizer.
  /// @param milliseconds Target position from the beginning of the stream.
  function seek(milliseconds)
    if this.closed then return _error("player is closed") end if
    if typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_AUDIO_MILLISECONDS then
      return _error("seek position is outside the supported millisecond range")
    end if
    result = try(this.mediaPlayer.seek(milliseconds))
    if typeof(result) == "error" then return _error(result.message) end if
    return true
  end function

  /// Return the current playback position in milliseconds.
  function position()
    if this.closed then return 0 end if
    return this.mediaPlayer.position()
  end function

  /// Return duration in milliseconds, or -1 while unknown.
  function duration()
    if this.closed then return -1 end if
    return this.mediaPlayer.duration()
  end function

  /// Return the current lifecycle state.
  function state()
    if this.closed then return State.Closed end if
    return _state(this.mediaPlayer.state())
  end function

  /// Report whether the backend detected an audio stream.
  function hasAudio()
    if this.closed then return false end if
    return this.mediaPlayer.hasAudio()
  end function

  /// Set linear volume from 0.0 through 1.0.
  /// Windows MIDI sequencers may expose only mute rather than per-player
  /// volume; the runtime never changes the process-wide MIDI mapper volume.
  /// @param volume Linear volume in the inclusive range 0.0 through 1.0.
  function setVolume(volume)
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.setVolume(volume))
    if typeof(result) == "error" then return _error(result.message) end if
    this.options.volume = volume
    return true
  end function

  /// Mute or unmute audio.
  /// @param muted Whether audio output is muted.
  function setMuted(muted)
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.setMuted(muted))
    if typeof(result) == "error" then return _error(result.message) end if
    this.options.muted = muted
    return true
  end function

  /// Set playback speed from 0.25 through 4.0.
  /// MIDI rate support depends on the installed backend synthesizer.
  /// @param rate Requested playback-rate multiplier.
  function setPlaybackRate(rate)
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.setPlaybackRate(rate))
    if typeof(result) == "error" then return _error(result.message) end if
    this.options.playbackRate = rate
    return true
  end function

  /// Enable or disable automatic restart after end of stream.
  /// @param enabled Whether end-of-stream restarts playback.
  function setLoop(enabled)
    if this.closed then return _error("player is closed") end if
    result = try(this.mediaPlayer.setLoop(enabled))
    if typeof(result) == "error" then return _error(result.message) end if
    this.options.loopEnabled = enabled
    return true
  end function

  /// Return the next queued event, or void when no event is available.
  function pollEvent()
    if this.closed then return end if
    shared = this.mediaPlayer.pollEvent()
    if shared is void then return end if
    return std.audio.Event(
      _eventKind(shared.kind),
      _state(shared.state),
      shared.code,
      shared.message)
  end function

  /// Release decoder state, playback threads and native handles.
  /// Multiple close calls are harmless.
  function close()
    if this.closed then return true end if
    result = try(this.mediaPlayer.close())
    if typeof(result) == "error" then return _error(result.message) end if
    this.closed = true
    return true
  end function
end struct

/// Return the native audio backend name.
function backend()
  return media.backend()
end function

/// Report whether the installed shared-media bridge is available.
function isAvailable()
  return media.isAvailable()
end function
