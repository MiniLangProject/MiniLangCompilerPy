import MiniGuiLib.minigui as gui
import std.video as video

struct Context
  app
  label
  input
end struct
function clicked(context, event)
  gui.Control.setText(context.label, "clicked:" + gui.Control.getText(context.input))
  result = gui.Dialog.yesNo(context.app, "Confirm", "Confirm native MinUX dialog")
  if result == "yes" then gui.Control.setText(context.label, "confirmed") end if
end function
function main(args)
  app = gui.Application.create()
  window = gui.Window.create(app, "main", "MiniLang / MinUX", 500, 360)
  label = gui.Label.create(app, window, "label", "Ready", 12, 12, 300, 24)
  button = gui.Button.create(app, window, "button", "Press me", 12, 44, 120, 28)
  input = gui.TextBox.create(app, window, "input", "initial", 12, 84, 300, 28)
  image = gui.Image.create(app, window, "image", "Video", 12, 124, 200, 180, "", "uniform")
  player = video.Player.open("/home/user/fixtures/colors.avi")
  player.attach(image.handle)
  player.setLoop(true)
  player.play()
  gui.Events.bindClick(app, button, clicked, Context(app, label, input))
  gui.Window.show(window)
  while gui.mg_alive(window.handle)
    gui.Application.pump(app, true)
  end while
  player.close()
  gui.Application.dispose(app)
  return 37
end function
