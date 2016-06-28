using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecuritySpace;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            SecurityAttributes sA = new SecurityAttributes();
                 
            byte[] key = Encoding.UTF8.GetBytes("7061737323313233");
            byte[] iv = Encoding.UTF8.GetBytes("7061737323313233");
                        
            // şifreleme yapan kısım (AES)
            string encryptedHex = sA.AESEncrypt("Sifrelenecek yazı", key, iv);
                              
            // şifreleme çözen kısım (AES)
            string plaintext = sA.AESDecrypt(encryptedHex, key, iv);
            
            Console.WriteLine();
        }
    }
}
