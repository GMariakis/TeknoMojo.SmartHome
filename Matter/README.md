# TeknoMojo.Matter

.NET 11 libraries for the CSA [Matter](https://csa-iot.org/all-solutions/matter/) protocol — device discovery, commissioning, secure sessions, and control over IP. First-party implementation: no third-party Matter SDK, no third-party D-Bus library. Cross-platform by design — a shared portable core with one thin, platform-native BLE backend per OS.

## Packages

| Package | Platform | Description |
| --- | --- | --- |
| **TeknoMojo.Matter.Core** | Any (`net11.0`) | Discovery, Matter TLV, SPAKE2+ (PASE) and CASE (SIGMA) crypto, certificate authority, BTP framing, the Interaction Model (Read/Invoke), commissioning cluster helpers, and the `MatterCommissioner` orchestrator. Everything that isn't platform-specific BLE lives here. |
| **TeknoMojo.Matter.Ble.Windows** | Windows | BLE commissioning transport via `Windows.Devices.Bluetooth` (WinRT). Verified live against real hardware. |
| **TeknoMojo.Matter.Ble.Linux** | Linux | BLE commissioning transport via BlueZ, over a hand-rolled D-Bus client (SASL auth, message framing, full type marshaling — no third-party D-Bus dependency). Compiles and unit-tests clean; not yet run against real BlueZ/hardware. |
| **TeknoMojo.Matter.Ble.MacOS** | macOS | BLE commissioning transport via CoreBluetooth, through Microsoft's official first-party .NET-for-macOS bindings. Compiles clean against the real SDK; not yet run against real hardware. |
| **TeknoMojo.Matter.Cli** | Any (`net11.0`) | `mtscan` — enumerates Matter nodes on the LAN. Peer to `hkscan` in TeknoMojo.HomeKit. |

`TeknoMojo.Matter.Core` depends on `TeknoMojo.mDNS.Core` for its discovery layer, exactly as `TeknoMojo.HomeKit.Core` does — mDNS stays a transport library shared by both protocols.

### Cross-platform architecture

Application code (and `mtscan`) should depend only on `IMatterBleCentral` / `IMatterTransport` from `TeknoMojo.Matter.Core.Ble`, never on a platform package directly. Each OS backend implements those same two interfaces:

- **Windows** — `WindowsMatterBleCentral` / `WindowsMatterBleTransport` (namespace `TeknoMojo.Matter.Ble.WinRT` — deliberately not `...Ble.Windows`, which collides with the global WinRT `Windows` namespace).
- **Linux** — `LinuxMatterBleCentral` / `LinuxMatterBleTransport`, built on a from-scratch D-Bus client (`TeknoMojo.Matter.Ble.Linux.DBus`) talking to BlueZ's documented interfaces (`org.bluez.Adapter1`, `Device1`, `GattService1`, `GattCharacteristic1`).
- **macOS** — `MacOSMatterBleCentral` / `MacOSMatterBleTransport` on `CoreBluetooth` (`CBCentralManager`/`CBPeripheral`).

A `MatterBleCandidate.PlatformAddress` is an opaque `object` per backend (a `ulong` BLE address on Windows, a BlueZ D-Bus object-path `string` on Linux, a live `CBPeripheral` on macOS) — callers never need to interpret it.

### End-to-end flow

```csharp
IMatterBleCentral central = new WindowsMatterBleCentral(); // or Linux/MacOS
central.StartScan();
var candidate = await central.WaitForDiscriminatorAsync(discriminator, TimeSpan.FromSeconds(30));
await using var transport = await central.ConnectAsync(candidate); // BTP handshake done

var fabric = new CommissionerFabricContext(fabricId, rootCertDer, rootPrivKeyPkcs8, controllerNodeId, ipk, adminVendorId);
var result = await MatterCommissioner.CommissionAsync(transport, setupCode, fabric, newDeviceNodeId: 100);
// device now holds our fabric's root + a NOC we issued; reachable via CASE at its operational IP.

// Later, over IP (after CASE — orchestration not yet wrapped in a single call, see M2f note below):
var onOff = new OnOffCluster(interactionClient, endpoint: 1);
await onOff.TurnOnAsync();
```

## Roadmap

- **M0** — Discovery + `mtscan`. ✅
- **M1** — Matter TLV codec. ✅
- **M2** — Commissioning:
  - M2a SPAKE2+ (PASE crypto). ✅
  - M2b Secure-channel message framing (AES-CCM). ✅
  - M2c Certificate authority (RCAC/NOC, DER + Matter-TLV). ✅
  - M2d CASE (SIGMA-I) session establishment. ✅
  - M2e BLE BTP transport — Windows/Linux/macOS backends. ✅ (Windows live-verified; Linux/macOS compile- and unit-verified, awaiting real-hardware runs)
  - M2f Commissioner orchestration. ✅ — follows the reference commissioner's stage order:

    ```
    ReadCommissioningInfo → ArmFailSafe → SetRegulatoryConfig → SetTCAcknowledgements¹
      → time configuration¹ → attestation (PAI, DAC, AttestationRequest + verification)
      → CSRRequest → AddTrustedRootCertificate → AddNOC → ICD registration¹
      → AddOrUpdate{WiFi,Thread}Network → re-ArmFailSafe → ConnectNetwork
      → operational discovery → CASE → CommissioningComplete
    ```

    ¹ conditional on what the device reports it needs.

    The device drives the flow rather than our assumptions: the fail-safe honours its own
    recommendation, the regulatory location is bounded by its `LocationCapability`, and the network
    step allows the `ConnectMaxTimeSeconds` it advertises.

    **Deviations, stated rather than assumed:** attestation is verified for signature, issuance and
    nonce freshness, but only anchors to a certified root when the caller supplies one — the CSA's
    PAA roots are deliberately not bundled, since which roots to trust is the caller's policy.
    Terms-and-conditions acceptance is relayed, never fabricated: a device that demands it and is
    given none fails loudly. Batched invokes spanning multiple messages are not supported (chunked
    *reads* are reassembled).
- **M3** — Interaction Model Read over an established session. ✅ (`MatterInteractionClient.ReadAttributeAsync`)
- **M4** — Invoke: OnOff cluster commands. ✅ (`OnOffCluster.TurnOnAsync`/`TurnOffAsync`/`ToggleAsync`)
- **M5** — Subscribe. ✅ (`MatterSubscription`) — the device primes with current values, confirms,
  then reports on change. The priming report is exposed as `InitialReports` data rather than raised
  as an event, so a caller attaching a handler after creation cannot miss it. Every report is
  acknowledged, because a device that stops being acknowledged tears the subscription down.
- **M6** — Multi-admin ergonomics — no extra protocol work needed beyond M2f: an existing admin (e.g. Apple Home) opens a commissioning window on the device via its own UI, and our commissioner then runs the same PASE + NOC-issuance flow against that window.

### Reliability

Matter's Message Reliability Protocol (Spec §4.12) is implemented and applied per transport: UDP
gets acknowledgements, retransmission on the spec's backoff schedule, duplicate suppression and
stand-alone acks; BTP and TCP suppress it entirely, since BTP acknowledges its own fragments and
TCP is a reliable stream. `IMatterTransport.RequiresReliableMessaging` is what decides.

A stand-alone acknowledgement never requests one in return. That sounds obvious and is not — the
BLE transport once ping-ponged bare acks with an accessory indefinitely, so it is now structurally
prevented in both message paths and pinned by tests.

### Persistence

`IMatterFabricStore` keeps fabrics and the nodes commissioned onto them, with
`FileMatterFabricStore` as the default (one JSON file per fabric, saved via an atomic move so an
interrupted write cannot orphan a fabric). **These files hold the fabric root CA private key, the
controller's operational private key and the IPK in plaintext** — anyone who can read them can
administer every device on the fabric. That is stated rather than hidden; back the interface with a
keychain or vault anywhere that matters.

### Not yet built

Batched invokes spanning multiple messages, and CASE session resumption (`Sigma2_Resume`).
Certificate handling is otherwise complete — note that generated certificates must use the **named**
P-256 curve rather than explicit domain parameters, or a peer rebuilding the TBS from Matter TLV
computes different bytes and rejects the signature.

## License

MIT — Copyright (c) 2026 TeknoMojo
