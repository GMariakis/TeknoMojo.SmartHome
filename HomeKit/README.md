# TeknoMojo.HomeKit

.NET 11 libraries for working with Apple HomeKit accessories and integrating third-party smart-home devices.

## Packages

| Package | Description |
| --- | --- |
| **TeknoMojo.HomeKit.Core** | Apple HomeKit Accessory Protocol (HAP) support, including DNS-SD discovery of HAP accessories on the LAN. |
| **TeknoMojo.HomeKit.Hap** | Pairing with HAP accessories, encrypted sessions, and reading and writing characteristics. |
| **TeknoMojo.HomeKit.Meross** | Meross smart-device integration (cloud and local discovery, control of Meross outlets) built on top of the Core library. |

`TeknoMojo.HomeKit.Hap` and `TeknoMojo.HomeKit.Meross` depend on `TeknoMojo.HomeKit.Core`.

## License

MIT — Copyright (c) 2026 TeknoMojo
