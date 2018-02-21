using System;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace RSAencrypt
{
    class RSAcrypt
    {
        UnicodeEncoding ByteConverter = new UnicodeEncoding();
        RSACryptoServiceProvider RSA { get; set; }
        RSACryptoServiceProvider RSApublic = new RSACryptoServiceProvider();

        public RSAcrypt(X509Certificate2 cert)
        {
            if (cert.HasPrivateKey)
            {
                RSA = (RSACryptoServiceProvider)cert.PrivateKey;
            }
            RSApublic = (RSACryptoServiceProvider)cert.PublicKey.Key;
        }     

        public string RSAEncrypt(string data)
        {
            byte[] plaintext = ByteConverter.GetBytes(data);
            byte[] encryptedtext = Encryption(plaintext, RSApublic.ExportParameters(false), false);
            return Encoding.Default.GetString(encryptedtext);
        }

        public string RSADecrypt(string data)
        {
            if (RSA != null)
            {
                byte[] decryptedtex = Decryption(Encoding.Default.GetBytes(data), RSA.ExportParameters(true), false);
                return ByteConverter.GetString(decryptedtex);
            }
            else
            {
                throw new Exception("Certificate does not contain a private key");
            }
        }

        byte[] Encryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    encryptedData = RSA.Encrypt(Data, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        byte[] Decryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKey);
                    decryptedData = RSA.Decrypt(Data, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }
    }
}
