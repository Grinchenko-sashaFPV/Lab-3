using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    internal class SecureServer
    {
        private const int Port = 5000;
        private static readonly X509Certificate2 ServerCertificate = new X509Certificate2("server_certificate.pem");

        public static void Start()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, Port);
            listener.Start();
            Console.WriteLine("Secure Server started and listening...");

            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                NetworkStream networkStream = client.GetStream();
                SslStream sslStream = new SslStream(networkStream, false, ValidateClientCertificate);

                try
                {
                    sslStream.AuthenticateAsServer(ServerCertificate, clientCertificateRequired: true, checkCertificateRevocation: true);
                    Console.WriteLine("SSL handshake completed. Client authenticated.");

                    // Далі ми реалізуємо прийом та обробку зашифрованих повідомлень...
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Authentication failed: {0}", ex.Message);
                    sslStream.Close();
                    client.Close();
                }
            }
        }

        private static bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Client certificate validated successfully.");
                return true;
            }

            Console.WriteLine("Client certificate validation failed: {0}", sslPolicyErrors);
            return false;
        }
    }
}
