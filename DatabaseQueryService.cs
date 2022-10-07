using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class DatabaseQueryService : FileSignatureResolverBase
    {

        public List<Signature> SignatureList { get; set; }
        public string SearchExtKeyWord { get; set; } = string.Empty;
        public string SearchHexKeyWord { get; set; } = string.Empty;

        /// <summary>
        /// DatabaseQueryService constructor
        /// </summary>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        public DatabaseQueryService(in List<Signature> signatureList) 
        { 
            SignatureList = signatureList;
            SearchExtKeyWord= string.Empty;
            SearchHexKeyWord= string.Empty;
        }

        /// <summary>
        /// DatabaseQueryService constructor
        /// </summary>
        /// <param name="searchExtKeyWord">File extension to be searched</param>
        /// <param name="searchHexKeyWord">File header (hexadecimal value) to be searched</param>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        public DatabaseQueryService(string searchExtKeyWord, string searchHexKeyWord, in List<Signature> signatureList) 
        {
            SignatureList = signatureList;
            SearchExtKeyWord = searchExtKeyWord;
            SearchHexKeyWord = searchHexKeyWord;
        }

        /// <summary>
        /// Returns a complete list of known file signatures from the extensions.json file
        /// </summary>
        public void DisplayHeaders()
        {
            try
            {
                Console.WriteLine($"\nTotal File Signatures:  {SignatureList.Count}");
                foreach (Signature signatureRow in SignatureList)
                {
                    PrintResult(signatureRow);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a list of file signatures, from the extensions.json file, in which the specified file extension is contained within the JSON extension key/value pair
        /// </summary>
        public void DisplayHeadersSearchByExtension()
        {
            try
            {
                int signature1 = SignatureList.FindAll(x => x.Name.ToLower().Contains(SearchExtKeyWord.ToLower())).Count;
                if (signature1 > 0)
                {
                    Console.WriteLine($"\nTotal File Signatures:  {signature1}");
                    foreach (Signature tempSignature in SignatureList.FindAll(x => (x.Name.ToLower().Contains(SearchExtKeyWord.ToLower()))))
                    {
                        PrintResult(tempSignature);
                    }
                }
                else { Console.WriteLine($"\nNo matching records were found for extension:  {SearchExtKeyWord}"); }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Returns a list of file signatures, from the extensions.json file, in which the specified byte sequence is contained within the related JSON signature (signs) key/value pair
        /// </summary>
        public void DisplayHeadersSearchByHex()
        {
            try
            {
                SearchHexKeyWord = GenericByteOperations.SanitizeHex(SearchHexKeyWord); // TODO:  Test this - not duplicated 
                int signature1 = SignatureList.FindAll(x => x.Hex.ToLower().Contains(SearchHexKeyWord.ToLower())).Count;

                if (signature1 > 0)
                {
                    Console.WriteLine($"\nTotal File Signatures:  {signature1}");
                    foreach (Signature tempSignature in SignatureList.FindAll(x => (x.Hex.ToLower().Contains(SearchHexKeyWord.ToLower()))))
                    {
                        PrintResult(tempSignature);
                    }
                }
                else { Console.WriteLine($"\nNo matching records were found for hex string:  {SearchHexKeyWord}"); }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        private static void PrintResult(Signature ouputList)
        {
            Console.WriteLine("\n{0,-20} {1,-120}", "ID:", ouputList.Id);
            Console.WriteLine("{0,-20} {1,-120}", "Extension:", ouputList.Name);
            Console.WriteLine("{0,-20} {1,-120}", "Offset:", ouputList.Offset + " (base 10) / " + String.Format("0x{0:X}", Convert.ToInt32(ouputList.Offset)) + " (base 16)");
            Console.WriteLine("{0,-20} {1,-120}", "Value at offset:", ouputList.Hex + " (base 16) ");
            Console.WriteLine("{0,-20} {1,-120}", "ASCII:", GenericByteOperations.HexToAscii(HexString: ouputList.Hex)); //duplicated
            Console.WriteLine("{0,-20} {1,-120}", "MIME:", ouputList.Mime);
            Console.WriteLine("\n---------------------------------------------");
        }
    }
}
