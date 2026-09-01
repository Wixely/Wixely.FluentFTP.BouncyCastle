using System.Text;
using System.Text.Json;
using FluentFTP;
using Wixely.FluentFTP.BouncyCastle;

if (args.Length != 1 || !File.Exists(args[0])) {
	Console.Error.WriteLine("Usage: hardware-test <private-settings.json>");
	return 2;
}

var settings = JsonSerializer.Deserialize<PrivateSettings>(await File.ReadAllTextAsync(args[0]))
	?? throw new InvalidOperationException("The private settings file is empty.");
var host = DecodeRequired(settings.Host, nameof(settings.Host));
var accessCode = DecodeRequired(settings.AccessCode, nameof(settings.AccessCode));
var diagnostics = new List<string>();

using var client = new AsyncFtpClient(host, "bblp", accessCode, 990);
client.Config.EncryptionMode = FtpEncryptionMode.Implicit;
client.Config.DataConnectionType = FtpDataConnectionType.PASV;
client.Config.ValidateAnyCertificate = true;
client.Config.ConnectTimeout = 10_000;
client.Config.ReadTimeout = 10_000;
client.Config.DataConnectionConnectTimeout = 10_000;
client.Config.DataConnectionReadTimeout = 10_000;
client.Config.CustomStream = typeof(BouncyCastleFtpStream);
client.Config.CustomStreamConfig = new BouncyCastleFtpStreamConfig {
	RequireSessionResumption = true,
	AllowLegacyResumption = true,
	Diagnostic = diagnostics.Add,
};

try {
	await client.Connect();
	var firstListing = await client.GetListing("/");
	var secondListing = await client.GetListing("/");

	Console.WriteLine("PASS: control authentication and two read-only root listings succeeded.");
	Console.WriteLine($"Entries returned: {firstListing.Length}, then {secondListing.Length}");
	foreach (var message in diagnostics.Distinct()) {
		Console.WriteLine(message);
	}

	await client.Disconnect();
	return 0;
}
catch (Exception exception) {
	Console.Error.WriteLine($"FAIL: {exception.GetType().Name}: {exception.Message}");
	foreach (var message in diagnostics.Distinct()) {
		Console.Error.WriteLine(message);
	}

	return 1;
}
finally {
	accessCode = string.Empty;
}

static string DecodeRequired(string? encoded, string name) {
	if (string.IsNullOrWhiteSpace(encoded)) {
		throw new InvalidOperationException($"Private setting '{name}' is required.");
	}

	return Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
}

internal sealed record PrivateSettings(string? Host, string? AccessCode);
