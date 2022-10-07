using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class PatchByteCustomRangeService : FileSignatureResolverBase, IPatch
    {
        public string FileFullPath  { get; set; }
        public string HexSequence { get; set; }
        public string StartingHexOffset { get; set; }
        private string RevertByteString = String.Empty;
        private bool PatchByteSuccess = false;

        /// <summary>
        /// PatchByteCustomRangeService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file in which the hexadecimal values will be patched</param>
        /// <param name="hexSequence">Custom hexadecimal sequence to patch</param>
        /// <param name="startingHexOffSet">Hexadecimal offset from which to start patching</param>
        public PatchByteCustomRangeService(string fileFullPath, string hexSequence, string startingHexOffSet) 
        { 
            FileFullPath = fileFullPath;
            HexSequence = hexSequence;
            StartingHexOffset = startingHexOffSet;
        }

        /// <summary>
        /// Patch a specified file with a custom hexadecimal sequence at a specified starting offset
        /// </summary>
        public void PatchBytes()
        {
            try
            {
                 RevertByteString = GenericByteOperations.ReadCustomByteRange(fileFullPath: FileFullPath,
                    startingHexOffSet: Convert.ToInt32(StartingHexOffset, 16),
                    lengthToRead: Convert.FromHexString(HexSequence.Replace("0x", "").Replace(" ", "")).Length); //duplicated

                Console.WriteLine($"\nEnsure you have backed up file {FileFullPath}");
                Console.Write($"Confirm:  Write '{HexSequence}' (base 16) byte values starting at Offset '{String.Format("0x{0:X}", Convert.ToInt32(StartingHexOffset, 16))}' (type y or n):");
                if (Console.ReadKey().Key == ConsoleKey.Y)
                {
                    using FileStream fs = File.OpenWrite(FileFullPath);
                    fs.Position = Convert.ToInt32(StartingHexOffset, 16);
                    var data = HexSequence.Replace("0x", "").Replace(" ", "");
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
            Console.WriteLine($"Use '{RevertByteString}' (base 16) byte values starting at offset {String.Format("0x{0:X}", Convert.ToInt32(StartingHexOffset, 16))} to revert back to the original byte sequence");
            Console.WriteLine($"Command: -pc \"{FileFullPath}\" \"{RevertByteString}\" \"{String.Format("0x{0:X}", Convert.ToInt32(StartingHexOffset, 16))}\"");
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
