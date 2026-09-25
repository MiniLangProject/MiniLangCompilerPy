// Integration test for the portable std.audio facade.
import std.audio as audio
import std.time as time

function failure(message)
  return error(1, "[FAIL] std.audio: " + message)
end function

function waitReady(player, label)
  deadline = time.ticks() + 5000
  while time.ticks() < deadline
    event = player.pollEvent()
    if event is not void then
      if event.kind == audio.EventKind.Error then
        return failure(label + " prepare: " + event.message)
      end if
      if event.kind == audio.EventKind.Ready then return true end if
    end if
    time.sleep(5)
  end while
  return failure(label + " metadata timeout")
end function

function waitEnded(player, label)
  deadline = time.ticks() + 5000
  while time.ticks() < deadline
    event = player.pollEvent()
    if event is not void then
      if event.kind == audio.EventKind.Error then
        return failure(label + " playback: " + event.message)
      end if
      if event.kind == audio.EventKind.Ended then return true end if
    end if
    time.sleep(5)
  end while
  return failure(label + " end-of-stream timeout")
end function

function exercise(source, expectedFormat, label, exerciseControls, waitForEnd)
  options = audio.PlayerOptions.defaults()
  options.muted = true
  player = try(audio.Player.open(source, options))
  if typeof(player) == "error" then return failure(label + " open: " + player.message) end if
  defer player.close()

  if typeName(player) != "std.audio.Player" then
    return failure(label + " Player type identity: " + typeName(player))
  end if
  if player.format() != expectedFormat then return failure(label + " format") end if
  if player.backend() != audio.backend() then return failure(label + " backend") end if

  ready = try(waitReady(player, label))
  if typeof(ready) == "error" then return ready end if
  if not player.hasAudio() then return failure(label + " audio stream not detected") end if
  if player.duration() <= 0 then return failure(label + " invalid duration") end if

  changed = try(player.setVolume(0.5))
  if typeof(changed) == "error" then return failure(label + " volume: " + changed.message) end if
  changed = try(player.setMuted(true))
  if typeof(changed) == "error" then return failure(label + " mute: " + changed.message) end if
  changed = try(player.setLoop(true))
  if typeof(changed) == "error" then return failure(label + " loop on: " + changed.message) end if
  changed = try(player.setLoop(false))
  if typeof(changed) == "error" then return failure(label + " loop off: " + changed.message) end if
  changed = try(player.setPlaybackRate(1.25))
  if typeof(changed) == "error" then return failure(label + " rate 1.25: " + changed.message) end if
  changed = try(player.setPlaybackRate(1.0))
  if typeof(changed) == "error" then return failure(label + " rate reset: " + changed.message) end if

  started = try(player.play())
  if typeof(started) == "error" then return failure(label + " play: " + started.message) end if
  time.sleep(100)

  if exerciseControls then
    paused = try(player.pause())
    if typeof(paused) == "error" then return failure(label + " pause: " + paused.message) end if
    if player.position() < 0 then return failure(label + " negative position") end if
    sought = try(player.seek(100))
    if typeof(sought) == "error" then return failure(label + " seek: " + sought.message) end if
    resumed = try(player.play())
    if typeof(resumed) == "error" then return failure(label + " resume: " + resumed.message) end if
  end if

  if waitForEnd then
    ended = try(waitEnded(player, label))
    if typeof(ended) == "error" then return ended end if
    if player.state() != audio.State.Ended then return failure(label + " ended state") end if
  end if

  stopped = try(player.stop())
  if typeof(stopped) == "error" then return failure(label + " stop: " + stopped.message) end if
  if not player.close() then return failure(label + " close") end if
  if not player.close() then return failure(label + " idempotent close") end if
  if player.state() != audio.State.Closed then return failure(label + " closed state") end if
  afterClose = try(player.play())
  if typeof(afterClose) != "error" then return failure(label + " closed player accepted play") end if
  if player.pollEvent() is not void then return failure(label + " closed player returned an event") end if
  return true
end function

function main(args)
  if len(args) < 3 then
    result = failure("expected WAV, MP3 and MIDI fixture paths")
    print result.message
    return 1
  end if

  if not audio.isAvailable() then
    result = failure("shared media bridge ABI unavailable")
    print result.message
    return 1
  end if
  if not audio.isSupportedFormat(audio.Format.Wave) then return 1 end if
  if not audio.isSupportedFormat(audio.Format.Mp3) then return 1 end if
  if not audio.isSupportedFormat(audio.Format.Midi) then return 1 end if
  if audio.isSupportedFormat(audio.Format.Unknown) then return 1 end if
  if audio.formatFromSource("SOUND.WAVE") != audio.Format.Wave then return 1 end if
  if audio.formatFromSource("SOUND.MP3") != audio.Format.Mp3 then return 1 end if
  if audio.formatFromSource("SOUND.MP3?cache=1#part") != audio.Format.Mp3 then return 1 end if
  if audio.formatFromSource("SOUND.MIDI") != audio.Format.Midi then return 1 end if
  if audio.formatName(audio.Format.Midi) != "midi" then return 1 end if

  invalid = audio.PlayerOptions.defaults()
  invalid.volume = 2.0
  rejected = try(audio.Player.open(args[0], invalid))
  if typeof(rejected) != "error" or rejected.code != audio.AUDIO_ERROR then
    result = failure("invalid options were accepted")
    print result.message
    return 1
  end if

  missing = try(audio.Player.open(args[0] + ".missing"))
  if typeof(missing) != "error" or missing.code != audio.AUDIO_ERROR then
    result = failure("missing file was accepted")
    print result.message
    return 1
  end if
  network = try(audio.Player.open("https://example.invalid/audio.mp3"))
  if typeof(network) != "error" or network.code != audio.AUDIO_ERROR then
    result = failure("network source was enabled by default")
    print result.message
    return 1
  end if

  result = try(exercise(args[0], audio.Format.Wave, "WAV", true, false))
  if typeof(result) == "error" then print result.message; return 1 end if
  result = try(exercise(args[1], audio.Format.Mp3, "MP3", false, false))
  if typeof(result) == "error" then print result.message; return 1 end if
  result = try(exercise(args[2], audio.Format.Midi, "MIDI", true, true))
  if typeof(result) == "error" then print result.message; return 1 end if

  print "[OK] std.audio WAV, MP3 and MIDI playback via " + audio.backend()
  return 0
end function
