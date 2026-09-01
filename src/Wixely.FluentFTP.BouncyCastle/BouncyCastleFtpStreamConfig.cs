using FluentFTP.Streams;

namespace Wixely.FluentFTP.BouncyCastle;

/// <summary>Configures the Bouncy Castle TLS stream used by FluentFTP.</summary>
public sealed class BouncyCastleFtpStreamConfig : IFtpStreamConfig {
	/// <summary>
	/// Gets a value indicating whether a data connection must fail when the server does not resume
	/// the control connection's TLS session.
	/// </summary>
	public bool RequireSessionResumption { get; init; } = true;

	/// <summary>
	/// Gets a value indicating whether TLS 1.2 sessions without RFC 7627 Extended Master Secret may
	/// be resumed. Keep disabled unless compatibility with a known legacy server requires it.
	/// </summary>
	public bool AllowLegacyResumption { get; init; }

	/// <summary>Gets an optional callback for non-sensitive connection diagnostics.</summary>
	public Action<string>? Diagnostic { get; init; }
}
