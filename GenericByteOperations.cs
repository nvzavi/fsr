using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace fsr
{
    public static class GenericByteOperations
    {
        /// <summary>
        /// Returns a ASCII representation of a hexadecimal string
        /// </summary>
        /// <param name="HexString">Hexadecimal string that will be represented as ASCII</param>
        /// <param name="lengthOfHexString">OPTIONAL:  Length of hexdecimal string to read</param>
        /// <returns>ASCII representation of a specified hexadecimal string</returns>
        public static string HexToAscii(string HexString, int lengthOfHexString = 0)
        {

            string ascii = string.Empty;
            string hex = String.Empty;

            if (lengthOfHexString != 0) { HexString = HexString[..lengthOfHexString]; }

            string[] splitValues = HexString.Chunk(2).Select(x => new string(x)).ToArray();

            foreach (string hValue in splitValues)
            {
                int value = Convert.ToInt32(hValue, 16);
                if (value > 31) //ignore non-printable characters
                {
                    char charValue = (char)value;
                    ascii += charValue.ToString();
                }
            }
            return ascii;
        }

        /// <summary>
        /// Returns a hexadecimal sequence that starts at a specified offset and ends at a specified byte length
        /// </summary>
        /// <param name="fileFullPath">Full path of the file from which the hexadecimal values are read</param>
        /// <param name="startingHexOffSet">Hexadecimal offset from which to start reading</param>
        /// <param name="lengthToRead">Byte length to read</param>
        /// <returns>Hexadecimal value at the specified offset and length</returns>
        public static string ReadCustomByteRange(string fileFullPath, int startingHexOffSet, int lengthToRead)
        {
            byte[] bytesFile = new byte[lengthToRead];

            using (FileStream fs = File.OpenRead(fileFullPath))
            {
                fs.Position = startingHexOffSet;
                fs.Read(bytesFile, 0, lengthToRead);
                fs.Close();
            }
            return BitConverter.ToString(bytesFile).Replace("-", "");
        }

        /// <summary>
        /// Returns all starting indices/indexes (zero based) of a specified hexadecimal value that was located within a larger hexadecimal string
        /// </summary>
        /// <param name="searchHex">Hexadecimal value to be searched for</param>
        /// <param name="fullHex">Full hexadecimal string to be searched</param>
        /// <returns>Starting indices (zero based) of a specified hexadecimal value</returns>
        public static IEnumerable Offetlocations(string searchHex, string fullHex)
        {
            int searchPos = 0;
            int retVal = fullHex.IndexOf(searchHex, searchPos);
            while (retVal != -1)
            {
                yield return retVal;
                searchPos = retVal + searchHex.Length;
                retVal = fullHex.IndexOf(searchHex, searchPos);
            }
        }

        /// <summary>
        /// Remove hex identifiers and spaces from the hex string to be searched
        /// </summary>
        /// <param name="searchHexKeyWord">File header (hexadecimal value) to be searched</param>
        public static string SanitizeHex(string searchHexKeyWord)
        {
            if (searchHexKeyWord.Contains("0x", StringComparison.CurrentCulture))
            {
                string formattedHexKeyWord = string.Empty;
                string[] testStr = searchHexKeyWord.Split("0x", StringSplitOptions.RemoveEmptyEntries);
                foreach (string testStr2 in testStr)
                {
                    formattedHexKeyWord += testStr2;
                }
                searchHexKeyWord = formattedHexKeyWord.Replace(" ", ""); //cater for residual spaces
            }
            else if (searchHexKeyWord.Contains(' ', StringComparison.CurrentCulture))
            {
                searchHexKeyWord = searchHexKeyWord.Replace(" ", "");
            }
            return searchHexKeyWord;
        }
    }
}
