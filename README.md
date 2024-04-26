# GipSyntheticEx

A library to emulate Xbox One controllers on the local machine,
using the xboxgipsynthetic.dll library as a base. This library
extends the API by using hooks to allow for custom controller
arrival and metadata messages, and possibly more in the future.

This means this library can be used to emulate non-standard
controller types, such as guitar and drum instruments, flight
and fight sticks, and dance pads.

**If you are using this library, you need to run your program
as administrator.**

## Documentation

TODO, maybe.

## Building

If you use VS2022 you will get a build error because the NuGet
MinHook is old. Just copy one of the lib files to the name ita
asks for and it'll work
lmao

## License

This software is licensed under the MIT license. See
LICENSE.txt for more details.

This software uses libMinHook, licensed under the BSD-2-Clause
license. See https://github.com/TsudaKageyu/minhook
