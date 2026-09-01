using System.Security.Authentication;
using Wixely.FluentFTP.BouncyCastle;

var specs = new (string Name, Action Run)[] {
	("session resumption is required by default", RequireSessionResumptionByDefault),
	("legacy resumption is opt-in", LegacyResumptionIsOptIn),
	("uninitialized stream reports closed capabilities", UninitializedStreamReportsClosedCapabilities),
	("uninitialized base stream is rejected", UninitializedBaseStreamIsRejected),
	("dispose is idempotent", DisposeIsIdempotent),
};

var passed = 0;
foreach (var (name, run) in specs) {
	try {
		run();
		Console.WriteLine($"PASS {name}");
		passed++;
	}
	catch (Exception exception) {
		Console.Error.WriteLine($"FAIL {name}: {exception.Message}");
	}
}

Console.WriteLine($"{passed}/{specs.Length} specifications passed.");
return passed == specs.Length ? 0 : 1;

static void RequireSessionResumptionByDefault() {
	Assert(new BouncyCastleFtpStreamConfig().RequireSessionResumption, "Expected resumption to be required.");
}

static void LegacyResumptionIsOptIn() {
	Assert(!new BouncyCastleFtpStreamConfig().AllowLegacyResumption, "Legacy resumption must default to disabled.");
}

static void UninitializedStreamReportsClosedCapabilities() {
	using var stream = new BouncyCastleFtpStream();
	Assert(!stream.CanRead(), "An uninitialized stream must not be readable.");
	Assert(!stream.CanWrite(), "An uninitialized stream must not be writable.");
	Assert(stream.GetSslProtocol() == SslProtocols.None, "An uninitialized stream must not report a TLS version.");
	Assert(stream.GetCipherSuite() == "0x0000", "An uninitialized stream must not report a negotiated cipher.");
}

static void UninitializedBaseStreamIsRejected() {
	using var stream = new BouncyCastleFtpStream();
	AssertThrows<InvalidOperationException>(() => stream.GetBaseStream());
}

static void DisposeIsIdempotent() {
	var stream = new BouncyCastleFtpStream();
	stream.Dispose();
	stream.Dispose();
}

static void Assert(bool condition, string message) {
	if (!condition) {
		throw new InvalidOperationException(message);
	}
}

static void AssertThrows<TException>(Action action) where TException : Exception {
	try {
		action();
	}
	catch (TException) {
		return;
	}

	throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
}
