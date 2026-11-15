import std.video as video
import std.audio as audio
import std.time as time
import std.assert as t

function main(args)
  player = audio.Player.open("/home/user/fixtures/tone.wav")
  t.assertEq(player.duration(), 1000, "PCM WAV duration")
  t.assertEq(player.play(), true, "native audio playback")
  time.sleep(100)
  t.assertEq(player.pause(), true, "audio pause")
  position = player.position()
  time.sleep(50)
  t.assertEq(player.position(), position, "paused position")
  t.assertEq(player.seek(800), true, "audio seek")
  t.assertEq(player.setVolume(0.5), true, "audio volume")
  t.assertEq(player.setMuted(true), true, "audio mute")
  t.assertEq(player.setPlaybackRate(2.0), true, "audio rate")
  player.play()
  deadline = time.ticks() + 10000
  while player.state() != audio.State.Ended and time.ticks() < deadline
    time.sleep(20)
  end while
  t.assertEq(player.state(), audio.State.Ended, "hardware completion")
  player.close()
  player = video.Player.open("/home/user/fixtures/colors.avi")
  t.assertEq(player.hasVideo(), true, "raw AVI video")
  t.assertEq(player.hasAudio(), false, "raw AVI stream layout")
  t.assertEq(player.duration(), 1000, "AVI duration")
  t.assertEq(player.videoWidth(), 2, "AVI width")
  t.assertEq(player.videoHeight(), 2, "AVI height")
  player.play()
  time.sleep(100)
  player.pause()
  t.assertEq(player.seek(500), true, "video seek")
  player.stop()
  t.assertEq(player.position(), 0, "video stop position")
  player.close()
  for index = 0 to 19
    t.assertEq(typeof(try(video.Player.open("/home/user/fixtures/bad-" + index))), "error", "reject malformed media " + index)
  end for
  print "MINUX_MEDIA_OK"
  return 37
end function
