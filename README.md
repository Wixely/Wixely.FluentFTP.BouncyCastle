# Wixely.FluentFTP.BouncyCastle

A managed Bouncy Castle TLS stream adapter for FluentFTP. It allows an FTPS
data connection to explicitly resume the TLS 1.2 session established by the
control connection.

The project was created for FTPS servers that return an error such as:

```text
522 SSL connection failed: session reuse required
```

## Status

This project is an early `0.1.0-alpha.1` implementation. It has been verified
against a Bambu Lab printer using implicit FTPS on port 990. Two consecutive
read-only root listings succeeded with verified control-session resumption.

Only TLS 1.2 is currently offered by the adapter. Concurrent data transfers and
TLS 1.3 resumption have not been verified.

## Installation

```xml
<PackageReference Include="Wixely.FluentFTP.BouncyCastle" Version="0.1.0-alpha.1" />
```

## Usage

```csharp
using FluentFTP;
using Wixely.FluentFTP.BouncyCastle;

var client = new AsyncFtpClient(host, username, password, 990);
client.Config.EncryptionMode = FtpEncryptionMode.Implicit;
client.Config.CustomStream = typeof(BouncyCastleFtpStream);
client.Config.CustomStreamConfig = new BouncyCastleFtpStreamConfig {
    RequireSessionResumption = true,
};
```

Certificate validation remains controlled by FluentFTP. Configure its
certificate-validation callback or certificate pinning policy as normal.

Some legacy servers require session resumption without RFC 7627 Extended Master
Secret. Bouncy Castle blocks that by default. Enable compatibility only for a
known server that requires it:

```csharp
client.Config.CustomStreamConfig = new BouncyCastleFtpStreamConfig {
    RequireSessionResumption = true,
    AllowLegacyResumption = true,
};
```

Allowing legacy resumption reduces TLS protections and should not be enabled as
a general fallback.

## Build and test

```powershell
dotnet build Wixely.FluentFTP.BouncyCastle.sln -c Release
dotnet run --project tests\Wixely.FluentFTP.BouncyCastle.Specs -c Release --no-build
dotnet pack src\Wixely.FluentFTP.BouncyCastle -c Release -o artifacts\packages
```

The hardware test accepts a path to an ignored JSON file containing Base64
encoded `Host` and `AccessCode` properties. It performs only two root directory
listings:

```powershell
dotnet run --project samples\Wixely.FluentFTP.BouncyCastle.HardwareTest -- C:\private\printer.settings.json
```

## License

MIT
