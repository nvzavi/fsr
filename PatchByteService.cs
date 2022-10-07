using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class PatchByteService : FileSignatureResolverBase, IPatch
    {
        public string FileFullPath { get; set; }
        public int SearchID { get; set; }
        public List<Signature> SignatureList { get; set; }
        private string RevertByteString = String.Empty;
        private bool PatchByteSuccess = false;

        /// <summary>
        /// PatchByteService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file in which the hexadecimal values will be patched</param>
        /// <param name="searchId">ID associated with a specific file type's attributes, offset and hexadecimal sequence that is located within the extensions.json file</param>
        /// <param name="signatureList">List containing the extensions.json file contents</param>
        public PatchByteService(string fileFullPath, int searchId, in List<Signature> signatureList) 
        { 
            FileFullPath = fileFullPath;
            SearchID = searchId;
            SignatureList = signatureList;
        }

        /// <summary>
        /// Patch a specified file with a selected hexadecimal sequence from the extensions.json file
        /// </summary>
        public void PatchBytes()
        {
            try
            {
                RevertByteString = GenericByteOperations.ReadCustomByteRange(fileFullPath: FileFullPath,
                    startingHexOffSet: SignatureList[SearchID - 1].Offset,
                    lengthToRead: Convert.FromHexString(SignatureList[SearchID - 1].Hex).Length); //duplicated

                Console.WriteLine($"\nEnsure you have backed up file {FileFullPath}");
                Console.Write($"Confirm:  Write '{SignatureList[SearchID - 1].Hex}' (base 16) byte values matching " +
                    $"extension '{SignatureList[SearchID - 1].Name}' "
                    + $"starting at Offset '{String.Format("0x{0:X}", SignatureList[SearchID - 1].Offset)}' (type y or n):");
                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(FileFullPath);

                    fs.Position = SignatureList[SearchID - 1].Offset;
                    var data = SignatureList[SearchID - 1].Hex;
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    PatchByteSuccess = true;
                }
                else
                {
                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }

        /// <summary>
        /// Print the command and byte options that will be required in order to revert to the previous byte sequence
        /// </summary>
        public void PrintRevertByteOptions()
        {
            Console.WriteLine($"Use '{RevertByteString}' (base 16) byte values starting at offset {String.Format("0x{0:X}", SignatureList[SearchID - 1].Offset)} to revert back to the original byte sequence");
            Console.WriteLine($"Command: -pc \"{FileFullPath}\" \"{RevertByteString}\" \"{String.Format("0x{0:X}", SignatureList[SearchID - 1].Offset)}\"");
        }

        /// <summary>
        /// Assess if the patch was applied successfully
        /// </summary>
        /// <returns>Boolean value (true or false) that indicates if the patch was successfull</returns>
        public bool IsPatchSuccessfull()
        {
            if (PatchByteSuccess)
                return true;
            else return false;
        }
    }
}
