using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using FluentFTP;
using FluentFTP.Client.BaseClient;
using FluentFTP.Streams;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Wixely.FluentFTP.BouncyCastle;

/// <summary>
/// Implements FluentFTP's custom stream contract with Bouncy Castle TLS and carries the control
/// connection's resumable TLS 1.2 session into each FTPS data connection.
/// </summary>
public sealed class BouncyCastleFtpStream : IFtpStream, IDisposable {
	private TlsClientProtocol? _protocol;
	private Stream? _stream;
	private TlsSession? _session;
	private ProtocolVersion? _version;
	private int _cipherSuite;
	private bool _disposed;

	/// <inheritdoc />
	public void Init(
		BaseFtpClient client,
		string targetHost,
		Socket socket,
		CustomRemoteCertificateValidationCallback customRemoteCertificateValidation,
		bool isControl,
		IFtpStream controlConnStream,
		IFtpStreamConfig config) {
		ObjectDisposedException.ThrowIf(_disposed, this);

		var adapterConfig = config as BouncyCastleFtpStreamConfig
			?? throw new ArgumentException($"Expected {nameof(BouncyCastleFtpStreamConfig)}.", nameof(config));
		var control = isControl ? null : controlConnStream as BouncyCastleFtpStream
			?? throw new InvalidOperationException("The data connection did not receive its Bouncy Castle control stream.");
		var sessionToResume = control?._session;

		if (!isControl && adapterConfig.RequireSessionResumption && sessionToResume is null) {
			throw new InvalidOperationException("The FTPS control connection did not provide a resumable TLS session.");
		}

		var networkStream = new NetworkStream(socket, ownsSocket: false);
		_protocol = new TlsClientProtocol(networkStream);
		var tlsClient = new ResumingTlsClient(
			client,
			sessionToResume,
			adapterConfig.AllowLegacyResumption,
			customRemoteCertificateValidation,
			adapterConfig.Diagnostic);

		try {
			_protocol.Connect(tlsClient);
			_stream = _protocol.Stream;
			_session = tlsClient.Context.ResumableSession;
			_version = tlsClient.Context.SecurityParameters.NegotiatedVersion;
			_cipherSuite = tlsClient.Context.SecurityParameters.CipherSuite;

			if (isControl) {
				adapterConfig.Diagnostic?.Invoke(_session?.IsResumable == true
					? "Control TLS session is resumable."
					: "Control TLS session is not resumable.");
			}
			else {
				var resumed = tlsClient.Context.SecurityParameters.IsResumedSession;
				adapterConfig.Diagnostic?.Invoke(resumed
					? "Data connection resumed the control TLS session."
					: "Data connection completed without resuming the control TLS session.");

				if (adapterConfig.RequireSessionResumption && !resumed) {
					throw new AuthenticationException("The FTPS data connection did not resume the control TLS session.");
				}
			}
		}
		catch {
			Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public Stream GetBaseStream() => _stream
		?? throw new InvalidOperationException("The TLS stream has not been initialized.");

	/// <inheritdoc />
	public bool CanRead() => _stream?.CanRead == true;

	/// <inheritdoc />
	public bool CanWrite() => _stream?.CanWrite == true;

	/// <inheritdoc />
	public SslProtocols GetSslProtocol() => _version switch {
		var version when version == ProtocolVersion.TLSv12 => SslProtocols.Tls12,
		var version when version == ProtocolVersion.TLSv13 => SslProtocols.Tls13,
		_ => SslProtocols.None,
	};

	/// <inheritdoc />
	public string GetCipherSuite() => $"0x{_cipherSuite:X4}";

	/// <inheritdoc />
	public void Dispose() {
		if (_disposed) {
			return;
		}

		_disposed = true;
		try {
			_protocol?.Close();
		}
		catch (IOException) {
			// FluentFTP owns the socket and may already have closed it.
		}
		finally {
			_protocol = null;
			_stream = null;
			_session = null;
		}
	}

	private sealed class ResumingTlsClient(
		object certificateValidationSender,
		TlsSession? sessionToResume,
		bool allowLegacyResumption,
		CustomRemoteCertificateValidationCallback certificateValidation,
		Action<string>? diagnostic)
		: DefaultTlsClient(new BcTlsCrypto(new SecureRandom())) {
		public TlsClientContext Context => m_context;

		public override TlsSession? GetSessionToResume() => sessionToResume;

		public override bool AllowLegacyResumption() => allowLegacyResumption;

		public override void NotifySessionToResume(TlsSession? session) {
			base.NotifySessionToResume(session);
			diagnostic?.Invoke(session is null
				? "No TLS session was offered for resumption."
				: $"Offered a resumable TLS session ({session.SessionID.Length}-byte ID).");
		}

		public override void NotifySessionID(byte[] sessionID) {
			base.NotifySessionID(sessionID);
			diagnostic?.Invoke($"Server selected a {sessionID.Length}-byte TLS session ID.");
		}

		protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv12];

		public override TlsAuthentication GetAuthentication() =>
			new CertificateAuthentication(certificateValidationSender, certificateValidation, diagnostic);
	}

	private sealed class CertificateAuthentication(
		object certificateValidationSender,
		CustomRemoteCertificateValidationCallback certificateValidation,
		Action<string>? diagnostic) : TlsAuthentication {
		public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;

		public void NotifyServerCertificate(TlsServerCertificate serverCertificate) {
			var certificateList = serverCertificate.Certificate.GetCertificateList();
			if (certificateList.Length == 0) {
				throw new AuthenticationException("The FTPS server did not provide a certificate.");
			}

			var certificates = certificateList
				.Select(static item => X509CertificateLoader.LoadCertificate(item.GetEncoded()))
				.ToArray();

			try {
				using var chain = new X509Chain();
				chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
				for (var index = 1; index < certificates.Length; index++) {
					chain.ChainPolicy.ExtraStore.Add(certificates[index]);
				}

				var chainValid = chain.Build(certificates[0]);
				var errorMessage = chainValid
					? string.Empty
					: string.Join("; ", chain.ChainStatus.Select(static status => status.StatusInformation.Trim()));

				if (!certificateValidation(certificateValidationSender, certificates[0], chain, errorMessage)) {
					throw new AuthenticationException("The FTPS server certificate was rejected.");
				}

				diagnostic?.Invoke("Server certificate accepted by FluentFTP validation policy.");
			}
			finally {
				foreach (var certificate in certificates) {
					certificate.Dispose();
				}
			}
		}
	}
}
