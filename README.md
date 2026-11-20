# TeknoMojo SmartHome

A collection of .NET 11 libraries and command-line tools for working with connected-home devices.

## HomeKit

The HomeKit libraries cover accessory discovery, HAP pairing and control, and Meross device integration. The hkscan CLI also uses Matter Core. [HomeKit projects](HomeKit/README.md)

## Matter, Bluetooth LE, and Thread

Matter Core provides discovery, commissioning, and control. Its companion BLE packages target Windows, Linux, and macOS. The commissioner can provision devices onto an existing Thread network. [Matter projects](Matter/README.md)

## Building

Use the .NET 11 SDK. Both Core libraries depend on TeknoMojo.mDNS.Core 2.0.0. Build that package from the mDNS repository and make it available in a local NuGet source before restoring. Build Matter Core before building the hkscan CLI, which references TeknoMojo.Matter.Core 0.2.0. The macOS BLE project also needs the .NET macOS workload. [TeknoMojo mDNS](https://github.com/GMariakis/TeknoMojo.mDNS)
