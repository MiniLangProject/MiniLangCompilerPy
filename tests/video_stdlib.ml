// Integration test for the portable native std.video bridge.
import std.video as video
import std.time as time

function fail(message)
  print "[FAIL] std.video: " + message
  return 1
end function

function main(args)
  if len(args) < 1 then return fail("expected media fixture path") end if

  invalid = video.PlayerOptions.defaults()
  invalid.volume = 2.0
  rejected = try(video.Player.open(args[0], invalid))
  if typeof(rejected) != "error" then
    return fail("invalid options were accepted")
  end if

  missing = try(video.Player.open(args[0] + ".missing"))
  if typeof(missing) != "error" then return fail("missing file was accepted") end if
  network = try(video.Player.open("https://example.invalid/video.mp4"))
  if typeof(network) != "error" then return fail("network source was enabled by default") end if

  options = video.PlayerOptions.defaults()
  options.muted = true
  player = try(video.Player.open(args[0], options))
  if typeof(player) == "error" then return fail("open returned " + player.message) end if
  defer player.close()

  if typeName(player) != "std.video.Player" then return fail("Player type identity: " + typeName(player)) end if
  if not video.isAvailable() then return fail("bridge ABI unavailable") end if
  if player.backend() != video.backend() then return fail("backend identity") end if

  ready = false
  deadline = time.ticks() + 5000
  while time.ticks() < deadline and not ready
    event = player.pollEvent()
    if event is void == false then
      if event.kind == video.EventKind.Error then return fail("prepare: " + event.message) end if
      if event.kind == video.EventKind.Ready then ready = true end if
    end if
    if not ready then time.sleep(5) end if
  end while
  if not ready then return fail("metadata timeout") end if
  if not player.hasVideo() then return fail("video stream not detected") end if
  if player.hasAudio() then return fail("unexpected audio stream") end if
  if player.videoWidth() != 160 or player.videoHeight() != 90 then return fail("video dimensions") end if
  if player.duration() < 1900 or player.duration() > 2100 then return fail("duration") end if

  invalidAttach = try(player.attach(0))
  if typeof(invalidAttach) != "error" then return fail("zero window handle was accepted") end if
  invalidRate = try(player.setPlaybackRate(0))
  if typeof(invalidRate) != "error" then return fail("invalid playback rate was accepted") end if
  invalidSeek = try(player.seek(video.MAX_VIDEO_MILLISECONDS + 1))
  if typeof(invalidSeek) != "error" then return fail("oversized seek was accepted") end if
  toggled = try(player.setLoop(true))
  if typeof(toggled) == "error" then return fail("enable loop: " + toggled.message) end if
  toggled = try(player.setLoop(false))
  if typeof(toggled) == "error" then return fail("disable loop: " + toggled.message) end if

  started = try(player.play())
  if typeof(started) == "error" then return fail("play returned " + started.message) end if
  time.sleep(150)
  paused = try(player.pause())
  if typeof(paused) == "error" then return fail("pause returned " + paused.message) end if
  if player.position() < 0 then return fail("negative position") end if
  sought = try(player.seek(500))
  if typeof(sought) == "error" then return fail("seek returned " + sought.message) end if
  resumed = try(player.play())
  if typeof(resumed) == "error" then return fail("resume returned " + resumed.message) end if

  ended = false
  deadline = time.ticks() + 5000
  while time.ticks() < deadline and not ended
    event = player.pollEvent()
    if event is void == false then
      if event.kind == video.EventKind.Error then return fail("playback: " + event.message) end if
      if event.kind == video.EventKind.Ended then ended = true end if
    end if
    if not ended then time.sleep(5) end if
  end while
  if not ended then return fail("end-of-stream timeout") end if

  stopped = try(player.stop())
  if typeof(stopped) == "error" or not stopped then return fail("stop") end if
  if not player.close() then return fail("close") end if
  if not player.close() then return fail("idempotent close") end if
  if player.state() != video.State.Closed then return fail("closed state") end if
  afterClose = try(player.play())
  if typeof(afterClose) != "error" then return fail("closed player accepted play") end if
  if player.pollEvent() is not void then return fail("closed player returned an event") end if

  if len(args) >= 2 then
    audioOptions = video.PlayerOptions.defaults()
    audioOptions.muted = true
    audioPlayer = try(video.Player.open(args[1], audioOptions))
    if typeof(audioPlayer) == "error" then return fail("audio open: " + audioPlayer.message) end if
    defer audioPlayer.close()

    audioReady = false
    deadline = time.ticks() + 5000
    while time.ticks() < deadline and not audioReady
      event = audioPlayer.pollEvent()
      if event is void == false then
        if event.kind == video.EventKind.Error then return fail("audio prepare: " + event.message) end if
        if event.kind == video.EventKind.Ready then audioReady = true end if
      end if
      if not audioReady then time.sleep(5) end if
    end while
    if not audioReady then return fail("audio metadata timeout") end if
    if not audioPlayer.hasAudio() then return fail("audio stream not detected") end if
    audioStarted = try(audioPlayer.play())
    if typeof(audioStarted) == "error" then return fail("audio play: " + audioStarted.message) end if
    time.sleep(100)
    audioStopped = try(audioPlayer.stop())
    if typeof(audioStopped) == "error" then return fail("audio stop: " + audioStopped.message) end if
    audioPlayer.close()
  end if

  print "[OK] native std.video playback via " + video.backend()
  return 0
end function
