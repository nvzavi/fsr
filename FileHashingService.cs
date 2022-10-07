using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class FileHashingService : FileSignatureResolverBase
    {
        public string FileFullPath { get; set; }
        public string HashingType { get; set; }

        /// <summary>
        /// FileHashingService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file to hash</param>
        /// <param name="hashingType">Hashing algorithm to implement.  Options include:  MD5, SHA1, SHA256, SHA384, and SHA512</param>
        public FileHashingService(string fileFullPath, string hashingType) 
        {
            FileFullPath = fileFullPath;
            HashingType = hashingType;
        }

        /// <summary>
        /// Returns a file hash of a specified file
        /// </summary>
        public void DisplayFileHash()
        {
            try
            {
                LocalFile localFile = new(FileFullPath);
                Console.WriteLine("\n{0,-15} {1,-64}", "Hash Type", "Hash Value");
                switch (HashingType.ToUpper())
                {
                    case nameof(HashType.MD5):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.MD5), localFile.GetMD5Hash());
                        break;
                    case nameof(HashType.SHA1):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA1), localFile.GetSHA1Hash());
                        break;
                    case nameof(HashType.SHA256):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA256), localFile.GetSHA256Hash());
                        break;
                    case nameof(HashType.SHA384):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA384), localFile.GetSHA384Hash());
                        break;
                    case nameof(HashType.SHA512):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA512), localFile.GetSHA512Hash());
                        break;
                    case nameof(HashType.ALL):
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.MD5), localFile.GetMD5Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA1), localFile.GetSHA1Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA256), localFile.GetSHA256Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA384), localFile.GetSHA384Hash());
                        Console.WriteLine("{0,-15} {1,-64}", nameof(HashType.SHA512), localFile.GetSHA512Hash());
                        break;
                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }
    }
}
