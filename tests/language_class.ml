interface Speakable
  function speak() returns string
end interface

interface Pet
  function category() returns string
end interface

class Animal implements Speakable
  name as string

  function speak() returns string
    return this.name
  end function
end class

class Mammal extends Animal
  age as int = 0

  function category() returns string
    return "mammal"
  end function
end class

class Dog extends Mammal implements Pet
  breed as string

  override function speak() returns string
    return super.speak() + "!"
  end function
end class

class Rock
end class

function callAnimal(value as Animal) returns string
  return value.speak()
end function

function main(args)
  dog = Dog(name = "Bello", breed = "Collie")
  if callAnimal(dog) != "Bello!" then return 1 end if
  if dog.name != "Bello" then return 2 end if
  if dog.breed != "Collie" then return 3 end if
  if not (dog is Animal) then return 4 end if
  if not (dog is Speakable) then return 5 end if
  if not (dog is Pet) then return 11 end if
  speaker as Speakable = dog
  if speaker.speak() != "Bello!" then return 6 end if
  if dog.age != 0 then return 7 end if
  if dog.category() != "mammal" then return 8 end if
  if not (dog is Mammal) then return 9 end if
  if not (Animal(name = "Other") is Speakable) then return 10 end if
  if Rock() is Speakable then return 12 end if
  print "[OK] classes, inheritance, overrides and runtime interfaces"
  return 0
end function
