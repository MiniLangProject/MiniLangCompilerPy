# Classes and interfaces

MiniLang classes add single inheritance and virtual instance methods to the
existing struct object model. Class instances still report `"struct"` from
`typeof`.

## Classes, overrides, and `super`

```ml
interface Named
  function name() returns string
end interface

class Animal implements Named
  nameText as string = "unknown"

  function name() returns string
    return this.nameText
  end function
end class

class Dog extends Animal
  override function name() returns string
    return super.name() + "!"
  end function
end class

function display(value as Animal) returns string
  return value.name()
end function

function main(args)
  print display(Dog(nameText = "Bello"))  // Bello!
  return 0
end function
```

An override requires `override function`, even when the base method is
abstract. Parameter count, parameter types, optional markers, variadic status,
return type, and visibility must match the inherited method. A method marked
`final function` cannot be overridden. `super.method(...)` calls the nearest
inherited implementation and accepts positional or named arguments, including
defaults declared by that implementation. Static methods cannot override
instance methods.

`abstract class` cannot be instantiated and may declare `abstract function`
methods without bodies. A concrete descendant must implement every inherited
abstract method. `final class` cannot be extended. Class inheritance is single:
one class may name at most one base class.

## Constructors and initializers

An optional `init(...)` method defines the class constructor's parameter list.
The constructor creates the object with its field defaults, then calls the
most-derived initializer. Every field must have a default when `init` exists.
An inherited `init` is used unless it is overridden. An overriding initializer
can call `super.init(...)`; that call is explicit.

```ml
class Person
  private secret as string = ""
  public name as string = ""

  function init(name as string, secret as string = "default")
    this.name = name
    this.secret = secret
  end function
end class

first = Person("Ada")
second = Person(secret = "private", name = "Bea")
factory = Person
third = factory("Cal")
```

`init` must be public, nonvariadic, nonabstract, and return `void`. Without
`init`, the constructor accepts only public fields, with inherited fields
first. Nonpublic fields need defaults and cannot be supplied by callers.
Direct calls accept named arguments and field or parameter defaults. Calls
through a class value accept positional arguments within the supported arity
range; omitting arguments that way requires trailing defaults.

## Visibility

Fields and methods are public by default. `private` allows access from the
declaring class, including another instance of that class. `protected` also
allows access from descendants. The compiler checks access through `this`,
stable local aliases, typed parameters, and qualified static calls. Overrides
must keep the inherited visibility. A private base method cannot be overridden
or called through `super`.

## Interface inheritance

Interfaces describe public instance methods and may inherit several contracts:

```ml
interface Named
  function name() returns string
end interface

interface Ranked
  function rank() returns int
end interface

interface RankedName extends Named, Ranked
end interface
```

A class or struct that implements `RankedName` must implement both inherited
methods. `value is RankedName`, `value is Named`, and `value is Ranked` all
recognize such an instance. Cycles and conflicting inherited method signatures
are compile errors. Interfaces declare contracts; they do not provide default
method bodies.

## Current limits

Classes have one base class, methods use exact override signatures rather than
covariant returns, and static methods do not participate in virtual dispatch.
The compiler currently infers nonpublic access through stable aliases and
declared parameter types; a value whose class is only known at runtime cannot
receive compile-time member-access validation.
