using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TcpSslTest
{
	class Program
	{
		private static bool _clientCertRequired;

		static async Task Main(string[] args)
		{
			// Load The Certificate
			var serverCertificate = LoadCertificateFromLocalMachineStore(ConfigurationManager.AppSettings["Cert"]);
			_clientCertRequired = bool.Parse(ConfigurationManager.AppSettings["RequireClientCert"]);

			// Create and start the TCP Server
			var tcp = new TcpListener(IPAddress.Any, 56000);
			tcp.Start();

			while (true)
			{
				Console.WriteLine("Waiting For client");
				using (var client = await tcp.AcceptTcpClientAsync())
				using (var sslStream = new SslStream(client.GetStream(), false, ValidateClient))
				//using (var sslStream = new SslStream(client.GetStream(), false, RemoteValidationCallback, LocalCertificateSelectionCallback, EncryptionPolicy.RequireEncryption))
				{
					// Starting with .net framework sslProtocols.none is send by default. Settings it to none here to show intent
					// Its best practice to use none and let OS determine best protocol to use
					await sslStream.AuthenticateAsServerAsync(serverCertificate, _clientCertRequired, SslProtocols.None, true);

					DisplaySecurityLevel(sslStream);
					DisplaySecurityServices(sslStream);
					DisplayCertificateInformation(sslStream);
					DisplayStreamProperties(sslStream);

					while (true)
					{
						byte[] secureDataBuffer = new byte[4096];

						Console.WriteLine("Waiting For Data");

						//var insecureDataTask = client.GetStream().ReadAsync(buffer, 0, buffer.Length);
						var data = await sslStream.ReadAsync(secureDataBuffer, 0, secureDataBuffer.Length);

						Console.WriteLine("Received Secured Data, which I will now output in plain text.");
						var bytes = new byte[data];
						Array.Copy(secureDataBuffer, 0, bytes, 0, data);
						var temp = Encoding.UTF8.GetString(bytes);
						Console.WriteLine(temp);

						Console.WriteLine("Enter Data To Send: ");
						Console.Write("Enter Text To Send: ");
						var test = Console.ReadLine();
						var testData = Encoding.UTF8.GetBytes(test);
						sslStream.Write(testData, 0, testData.Length);
					}
				}
			}
		}

		private static X509Certificate LoadCertificateFromLocalMachineStore(string thumbprint)
		{
			var store = new X509Store("MY", StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, true);
			var cert = certs[0];

			return cert;
		}

		public static bool ValidateClient(object sender, X509Certificate remoteCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			// If we are not requiring a client certificate remote certificate will be null
			if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable) && _clientCertRequired)
			{
				Console.WriteLine("Client Certificate Was Not Provided");
				return false;
			}

			Console.WriteLine($"SSL Policy Errors: {sslPolicyErrors}");
			return true;
		}



		static void DisplaySecurityLevel(SslStream stream)
		{
			Console.WriteLine("Security Level");
			Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
			Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
			Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
			Console.WriteLine("Protocol: {0}", stream.SslProtocol);
		}

		static void DisplaySecurityServices(SslStream stream)
		{
			Console.WriteLine("\r\n\r\nSecurity Services");
			Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
			Console.WriteLine("IsSigned: {0}", stream.IsSigned);
			Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
		}

		static void DisplayStreamProperties(SslStream stream)
		{
			Console.WriteLine("\r\n\r\n Stream Properties");
			Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
			Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
		}

		static void DisplayCertificateInformation(SslStream stream)
		{
			Console.WriteLine("\r\n\r\n Cert Info");
			Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

			X509Certificate localCertificate = stream.LocalCertificate;
			if (stream.LocalCertificate != null)
			{
				Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
					localCertificate.Subject,
					localCertificate.GetEffectiveDateString(),
					localCertificate.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Local certificate is null.");
			}
			// Display the properties of the client's certificate.
			X509Certificate remoteCertificate = stream.RemoteCertificate;
			if (stream.RemoteCertificate != null)
			{
				Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
					remoteCertificate?.Subject,
					remoteCertificate?.GetEffectiveDateString(),
					remoteCertificate?.GetExpirationDateString());
			}
			else
			{
				Console.WriteLine("Remote certificate is null.");
			}
		}
	}
}
