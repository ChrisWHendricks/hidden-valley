using System;
using System.Configuration;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TcpSslClientTest
{
	class Program
	{
		static async Task Main(string[] args)
		{

			X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
			var collection = store.Certificates.Find(X509FindType.FindByThumbprint,ConfigurationManager.AppSettings["Cert"], true);

			var client = new TcpClient();
			Console.WriteLine($"Press Any Key To Connect To {ConfigurationManager.AppSettings["TcpAddress"]}");
			await client.ConnectAsync(ConfigurationManager.AppSettings["TcpAddress"], 56000);

			Console.WriteLine("Creating SSL Stream");
			var stream = client.GetStream();
			var ssl = new SslStream(stream, false, ValidateServer);


			

			Console.WriteLine("SSL Stream Created, press enter to authenticate stream");
			Console.ReadLine();
			var server = ConfigurationManager.AppSettings["TargetHost"];
			await ssl.AuthenticateAsClientAsync(server); // Target Host needs to match the CN entry on the server certificate

			DisplaySecurityLevel(ssl);
			DisplaySecurityServices(ssl);
			DisplayCertificateInformation(ssl);
			DisplayStreamProperties(ssl);

			while (true)
			{
				Console.Write("Enter Text To Send: ");
				var test = Console.ReadLine();
				var testData = Encoding.UTF8.GetBytes(test);
				ssl.Write(testData, 0, testData.Length);

				byte[] secureDataBuffer = new byte[4096];
				var data = await ssl.ReadAsync(secureDataBuffer, 0, secureDataBuffer.Length);

				Console.WriteLine("Received Secured Data, which I will now output in plain text.");
				var bytes = new byte[data];
				Array.Copy(secureDataBuffer, 0, bytes, 0, data);
				var temp = Encoding.UTF8.GetString(bytes);
				Console.WriteLine(temp);
			}
		}

		public static bool ValidateServer(object sender, X509Certificate remoteCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			// If this callback is being used the client is responsible for determining if the server cert is valid
			if (sslPolicyErrors == SslPolicyErrors.None) return true;

			Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

			if (chain?.ChainStatus == null) return true;

			foreach (var status in chain.ChainStatus)
			{
				Console.WriteLine($"Chain Status: {status.Status} - {status.StatusInformation}");
			}

			// Do not allow this client to communicate with unauthenticated servers.
			return false;
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
