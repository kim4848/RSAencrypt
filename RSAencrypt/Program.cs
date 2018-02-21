using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace RSAencrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            //Only publickey - cant decrypt
            //X509Certificate2 cer = new X509Certificate2("TestPublicKeyCert.cer", "Test1234", X509KeyStorageFlags.Exportable);

            //with privatkey
            X509Certificate2 cer = new X509Certificate2("TestPrivatKeyCert.pfx", "Test1234", X509KeyStorageFlags.Exportable);
            RSAcrypt crypt = new RSAcrypt(cer);

            Console.WriteLine("Type text to be encrypted: \n ");
            var input =Console.ReadLine();
            
            var encryptedInput = crypt.RSAEncrypt(input);
            Console.WriteLine("\n\nEncrypted: \n" + encryptedInput);            
            Console.WriteLine("\nEncrypted Base64Encoded: \n" + Base64Encode(encryptedInput));

            try
            {
                var decryptedResult = crypt.RSADecrypt(encryptedInput);
                Console.WriteLine("\nDecrypted: \n" + decryptedResult);
            }
            catch(Exception e)
            {
                Console.WriteLine("\nMessage could not be decrypted : \n");
                Console.WriteLine(e.Message);
            }
            Console.ReadKey();
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }
    }
}
