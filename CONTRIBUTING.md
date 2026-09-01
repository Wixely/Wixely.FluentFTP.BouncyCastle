# Contributing

Build and run the local specifications before submitting a change:

```powershell
dotnet build Wixely.FluentFTP.BouncyCastle.sln -c Release
dotnet run --project tests\Wixely.FluentFTP.BouncyCastle.Specs -c Release --no-build
```

Hardware tests must be read-only unless a test explicitly documents and obtains
approval for a state-changing operation. Never commit printer addresses, access
codes, serial numbers, certificates, private configuration, or hardware-test
output containing identifying details.
