using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public class ByteCarvingService : FileSignatureResolverBase
    {
        public string FileFullPath { get; set; }
        public string StartingHexOffSet { get; set; }
        public string EndingHexOffSet { get; set; }
        public string FileOutputFullPath { get; set; }

        /// <summary>
        /// ByteCarvingService constructor
        /// </summary>
        /// <param name="fileFullPath">Full path of the file from which the hexadecimal byte values will be carved</param>
        /// <param name="startingHexOffSet">Hexadecimal offset that represents the start of the byte carving offset range</param>
        /// <param name="endingHexOffSet">Hexadecimal offset that represents the end of the byte carving offset range</param>
        /// <param name="fileOutputFullPath">Full path of the file to which the results will be written</param>
        public ByteCarvingService(string fileFullPath, string startingHexOffSet, string endingHexOffSet, string fileOutputFullPath) 
        {
            FileFullPath = fileFullPath;
            StartingHexOffSet = startingHexOffSet;
            EndingHexOffSet = endingHexOffSet;
            FileOutputFullPath = fileOutputFullPath;
        }

        /// <summary>
        /// Carve bytes from a specified file wihtin a specific hexadecimal offset range and write output to a new file
        /// </summary>
        public void CarveBytes()
        {
            try
            {
                int customSize = Convert.ToInt32(EndingHexOffSet, 16) - Convert.ToInt32(StartingHexOffSet, 16);
                byte[] buffer = new byte[customSize];

                using FileStream fs = File.OpenRead(FileFullPath);
                fs.Position = Convert.ToInt32(StartingHexOffSet, 16);
                fs.Read(buffer, 0, customSize);
                using FileStream fs1 = File.OpenWrite(FileOutputFullPath);
                {
                    fs1.Write(buffer, 0, buffer.Length);
                    fs1.Close();
                }
                fs.Close();
                Console.WriteLine($"\nOutput successfully written to {FileOutputFullPath}!!!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nError:  " + ex.Message);
            }
        }
    }
}
