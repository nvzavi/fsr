using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data;
using System.Collections;

namespace fh_res
{
    static class FileOperations
    {
        public static void LoadJson(string signatureListFilePath, ref List<Signature> signatureList)
        {
            List<StagingSignature> stagingSignature = new();

            using (StreamReader r = new(signatureListFilePath))
            {
                string json = r.ReadToEnd(); //read the JSON file
                var jo = JObject.Parse(json); //initialise an object to iterate through the nodes

                foreach (var kv in jo)
                {
                    if (kv.Value != null)
                    {
                        var deserializable = kv.Value.ToString(); //get deserializable children

                        if (kv.Key != null) //Get the Name.  Name is the root node e.g. 123
                        {
                            var sign = JsonConvert.DeserializeObject<StagingSignature>(deserializable);
                            sign.Name = kv.Key;
                            stagingSignature.Add(sign);//deserialise each node and add to signature object
                        }
                    }
                }

                int stagingCounter = 1;
                foreach (StagingSignature signs in stagingSignature)
                {

                    foreach (var val in signs.Signs) //access signature list attribute
                    {
                        int offset = Convert.ToInt32(val[..val.IndexOf(',')]); //substring(0,1)
                        string hexValue = val.Substring(val.IndexOf(',') + 1); //substring(2)
                        signatureList.Add(new Signature()
                        {
                            Id = stagingCounter,
                            Name = signs.Name,
                            Offset = offset,
                            Hex = hexValue,
                            Mime = signs.Mime
                        });
                        stagingCounter++;
                    }
                }
                r.Close();
            }
        }

        public static string HexToAscii(string hexValuesToRead, int lengthToPrint, bool IgnoreLength) //needs to change , ignorelength must come out
        {
            string ascii = string.Empty;
            string hex = String.Empty;

            if (IgnoreLength == true) //hexvalues is a defined length. no need to substring
            {
                hex = hexValuesToRead;
            }
            else if (IgnoreLength == false) { hex = hexValuesToRead[..lengthToPrint]; } //substring from 0 to lenght

            string[] splitValues = hex.Chunk(2).Select(x => new string(x)).ToArray();

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
        /// Display File Type
        /// </summary>
        public static void GetFileType(string fileFullPath, in List<Signature> signatureList, string fileOutputFullPath = "-1") //fileOutputFullPath is optional
        {
            //add proper try catch....better to evaluate the args in main NOT HERE
            byte[] bytesFile;
            using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
            {
                int headerSize = (int)fs.Length; //possible loss of data here FIX IT
                bytesFile = new byte[headerSize];
                fs.Read(bytesFile, 0, headerSize); //read header into bytesfile
                fs.Close();
            }

            string header = BitConverter.ToString(bytesFile).Replace("-", "");  //Convert the byte file to its hex string representation and remove the - symbols
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE TYPE                                   ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");

            try //add smaller try catch blocks
            {
                int columnCount = 9;
                var query = signatureList.Where(x => header.Contains(x.Hex)); //get all rows where JSON signature matches with a byte sequence in the file

                //add code here to find the original offset if not found at the expected offset

                Console.WriteLine($"\nFile:  {fileFullPath}");
                GetMoreFileDetails(fileFullPath: fileFullPath);

                int totalRecords = query.Count();
                Console.WriteLine($"Total Matches Found:  {totalRecords}");
                //string[,] stagingOuput = new string[query.Count(), columnCount];
                DataTable dataTable = new DataTable();
                DataColumn dataColumn;

                for (int i = 0; i <= columnCount - 1; i++)
                {
                    dataColumn = new DataColumn();
                    dataColumn.ColumnName = "Col" + i;
                    dataTable.Columns.Add(dataColumn);
                }

                foreach (Signature sig in query) //loop through all matched records and update datatable with additional attributes locatedPos
                {
                    //get the current offset within the byte sequence
                    string locatedPos = string.Empty;
                    int posCounter = 0;
                    int posValue = 0;

                    foreach (var offsetLoc in Offetlocations(searchTerm: sig.Hex, searchStr: header))
                    {
                        if (Convert.ToInt32(offsetLoc) % 2 != 0) //if its not an even number then skip execution and proceed to next iteration :  hex found at even number only
                        {
                            continue;
                        }
                        posValue = Convert.ToInt32(offsetLoc) / 2; //divide by 2 to get the byte value
                        string tempOutput = posValue == sig.Offset ? String.Format("0x{0:X}", Convert.ToInt32(offsetLoc) / 2) + " <--match" : String.Format("0x{0:X}",
                            Convert.ToInt32(offsetLoc) / 2); //assign match string to matched offset

                        if (posCounter == 0)
                        {
                            locatedPos = tempOutput.ToString(); //for the first output return only tempOutput  String.Format("0x{0:X}", Convert.ToInt32(tempOutput));
                        }
                        else if (posCounter <= 5)
                        {
                            locatedPos = locatedPos + " / " + tempOutput.ToString(); //for every tempOutput where the count is <6, add a trailing slash (/) 
                        }
                        else
                        {
                            locatedPos = locatedPos + " ***"; //if count is >= 6 then insert *** to denote multiple occurences of offset in several offsets 
                            break;
                        }
                        posCounter++;
                    }

                    string valueAtOffset = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: sig.Offset, lengthToRead: Convert.FromHexString(sig.Hex).Length); //get value at expected offset
                    var query1 = signatureList.Where(x => x.Offset == sig.Offset && x.Hex == valueAtOffset && x.Name == sig.Name); //compare above value to hex value in JSON
                                                dataTable.Rows.Add(new object[] { query1.Any() ? "high" : "low",
                                                sig.Name,
                                                sig.Offset.ToString(),
                                                sig.Hex,
                                                FileOperations.HexToAscii(hexValuesToRead: sig.Hex, lengthToPrint: sig.Hex.Length, true),
                                                sig.Mime,
                                                valueAtOffset,
                                                FileOperations.HexToAscii(hexValuesToRead: valueAtOffset, lengthToPrint: valueAtOffset.Length, true),
                                                locatedPos });//add results to datatable based on above query
                }

                // sort by first column:
                dataTable.DefaultView.Sort = "Col0";
                dataTable = dataTable.DefaultView.ToTable();

                //try catch here
                //write output to file
                if (fileOutputFullPath == "-1") //output to screen
                {
                    foreach (DataRow dRow in dataTable.Rows)
                    {
                        Console.WriteLine("\n{0,-30} {1,-64}", "Probability:", dRow[0].ToString());
                        Console.WriteLine("{0,-30} {1,-64}", "Extension:", dRow[1].ToString());
                        Console.WriteLine("{0,-30} {1,-64}", "Offset (expected):", dRow[2].ToString() + " (base 10) - " + String.Format("0x{0:X}",
                            Convert.ToInt32(dRow[2])) + "(base 16)"); //show output in decimal and hex
                        Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                        Console.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                        Console.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString()); //added mime

                        if (dRow[0].ToString() == "low")
                        {
                            Console.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset " + dRow[2].ToString() + ":", dRow[6].ToString());
                            Console.WriteLine("{0,-30} {1,-64}", "ASCII at Offset " + dRow[2].ToString() + ":", dRow[7].ToString());

                        }

                        Console.WriteLine("{0,-30} {1,-64}", "Located Offset\\s:", dRow[8].ToString());
                    }
                }
                else //output to file
                {
                    string fileName = fileOutputFullPath;
                    if (File.Exists(fileName))
                    {
                        Random random = new Random();
                        // Create a new file name
                        fileName = Path.GetDirectoryName(fileName) + "\\" + Path.GetFileName(fileName).Substring(0, Path.GetFileName(fileName).IndexOf(".")) + "_fhgen_" + random.Next(10000)
                            + Path.GetFileName(fileName).Substring(Path.GetFileName(fileName).IndexOf("."));
                    }

                    using (StreamWriter sw = File.CreateText(fileName))
                    {
                        sw.WriteLine("----------------------------------------------------------------------------------------------");
                        sw.WriteLine("----------                            FILE TYPE                                   ------------");
                        sw.WriteLine("----------------------------------------------------------------------------------------------");
                        sw.WriteLine("Note:  Use your favourite hex editor to view the byte sequence at the detected offset/s");
                        sw.WriteLine("");
                        sw.WriteLine($"File:  {fileFullPath}");
                        sw.WriteLine($"Processed Date:  {DateTime.Now}");
                        sw.WriteLine($"Total Matches Found:  {totalRecords}");
                        sw.WriteLine("");
                        // Add some text to file    
                        foreach (DataRow dRow in dataTable.Rows)
                        {
                            sw.WriteLine("{0,-30} {1,-64}", "Probability:", dRow[0].ToString());
                            sw.WriteLine("{0,-30} {1,-64}", "Extension:", dRow[1].ToString());
                            sw.WriteLine("{0,-30} {1,-64}", "Offset (expected):", dRow[2].ToString() + " (base 10) - " + String.Format("0x{0:X}",
                                Convert.ToInt32(dRow[2])) + "(base 16)"); //show output in decimal and hex
                            sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal (expected):", dRow[3].ToString());
                            sw.WriteLine("{0,-30} {1,-64}", "ASCII (expected):", dRow[4].ToString());
                            sw.WriteLine("{0,-30} {1,-64}", "Mime:", dRow[5].ToString()); //added mime

                            if (dRow[0].ToString() == "low")
                            {
                                sw.WriteLine("{0,-30} {1,-64}", "Hexadecimal at Offset " + dRow[2].ToString() + ":", dRow[6].ToString());
                                sw.WriteLine("{0,-30} {1,-64}", "ASCII at Offset " + dRow[2].ToString() + ":", dRow[7].ToString());

                            }

                            sw.WriteLine("{0,-30} {1,-64}", "Located Offset\\s:", dRow[8].ToString());
                            sw.WriteLine("");
                            sw.WriteLine("");
                        }
                        Console.WriteLine("Output written to file: " + fileName);
                    }
                }
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("Cannot find exact matching header!!!");
                Console.WriteLine("Current Header Information: (Displaying 16 bytes from offset 0)"); //catered for 4 spaces conatined in the header variable
                Console.WriteLine("{0,-15} {1,-64}", "Hexadecimal:", header[..20]); //this is wrong
                Console.WriteLine("{0,-15} {1,-64}", "ASCII:", FileOperations.HexToAscii(hexValuesToRead: header, lengthToPrint: 20, false)); //this is wrong
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("Error:  An invalid path was given in which to output the results!!!");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Error:  Access to path denied!!!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error info:" + ex.Message);
            }
            finally
            {
                Console.WriteLine("----------------------------------------------------------------------------------------------");
            }
        }

        private static void GetMoreFileDetails(string fileFullPath)
        {
            LocalFile localFile = new(fileFullPath);
            Console.WriteLine("\nFile Attributes --------------------------------------------------------------------------------");
            Console.WriteLine("{0,-15} {1,-64}", "File Name:", localFile.Name);
            Console.WriteLine("{0,-15} {1,-64}", "File Size:", localFile.FileSize + " bytes");
            Console.WriteLine("{0,-15} {1,-64}", "Created Date:", localFile.CreatedDate);
            Console.WriteLine("{0,-15} {1,-64}", "Accessed Date:", localFile.LastAccessed);
            Console.WriteLine("{0,-15} {1,-64}", "Modified Date:", localFile.LastModifiedDate);
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }

        private static IEnumerable Offetlocations(string searchTerm, string searchStr)
        {
            int searchPos = 0;
            int retVal = searchStr.IndexOf(searchTerm, searchPos);
            while (retVal != -1)
            {
                yield return retVal;
                searchPos = retVal + searchTerm.Length;
                retVal = searchStr.IndexOf(searchTerm, searchPos);
            }
        }

        private static string ReadCustomByteRange(string fileFullPath, int startingHexOffSet, int lengthToRead) 
        {
            byte[] bytesFile = new byte[lengthToRead];

            using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
            {
                fs.Position = startingHexOffSet; //offset to read from
                fs.Read(bytesFile, 0, lengthToRead);
                fs.Close();
            }
            return BitConverter.ToString(bytesFile).Replace("-", "");
        }

        /// <summary>
        /// Patch header from offset 0
        /// </summary> 
        public static void PatchBytes(string fileFullPath, int searchId, in List<Signature> signatureList) //arg1 file arg2 id DONE
        {
            string revertByte = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: signatureList[searchId - 1].Offset, 
                lengthToRead: Convert.FromHexString(signatureList[searchId - 1].Hex).Length); //last arg converts hex to byte then counts length FIX FromHexString see custompatch void
            Console.WriteLine($"Ensure you have backep up file {fileFullPath}");
            Console.Write($"Confirm:  Write '{signatureList[searchId - 1].Hex}' byte values matching extension '{signatureList[searchId - 1].Name}' " +
                $"starting at Offset '{signatureList[searchId - 1].Offset}' (type y or n):");

            if (Console.ReadKey().Key == ConsoleKey.Y)
            {
                try
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);

                    fs.Position = signatureList[searchId - 1].Offset; //offset JSON IS DECIMAL THIS IS CORRECT ...changed to int64
                    var data = signatureList[searchId - 1].Hex;//.Replace(" ", ""); 
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {signatureList[searchId - 1].Offset} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{signatureList[searchId - 1].Offset}\"");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\nError info:" + ex.Message);
                }
            }
            else
            {
                Environment.Exit(0);
            }
        }

        public static void PatchBytesCustomRange(string fileFullPath, string hexSequence, string startingHexOffSet) 
        {
            //revertByte is called again and again for different function...look at calling it once
            string revertByte = ReadCustomByteRange(fileFullPath: fileFullPath, startingHexOffSet: Convert.ToInt32(startingHexOffSet, 16), 
                lengthToRead: Convert.FromHexString(hexSequence.Replace("0x", "").Replace(" ", "")).Length); //last arg converts hex to byte then counts length

            Console.WriteLine($"Ensure you have backep up file {fileFullPath}");
            Console.Write($"Confirm:  Write '{hexSequence}' byte values starting at Offset '{startingHexOffSet}' (type y or n):");
            if (Console.ReadKey().Key == ConsoleKey.Y)
            {
                try
                {
                    using FileStream fs = File.OpenWrite(fileFullPath);

                    fs.Position = Convert.ToInt32(startingHexOffSet, 16); //offset WRONG CHECK THE OFFSET IN THE JSON IS IT HEX OR DECIMAL...changed to int64
                    var data = hexSequence.Replace("0x", "").Replace(" ", "");
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {startingHexOffSet} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{fileFullPath}\" \"{revertByte}\" \"{startingHexOffSet}\"");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\nError info:" + ex.Message);
                }
            }
            else
            {
                Environment.Exit(0);
            }

        }

        public static void ByteCarverByOffsets(string fileFullPath, string startingHexOffSet, string endingHexOffSet, string fileOutputFullPath) 
        {
            int customSize = Convert.ToInt32(endingHexOffSet, 16) - Convert.ToInt32(startingHexOffSet, 16);
            byte[] buffer = new byte[customSize];

            using (FileStream fs = File.OpenRead(fileFullPath))//@argFilePath
            {
                fs.Position = Convert.ToInt32(startingHexOffSet, 16); //offset to read from
                fs.Read(buffer, 0, customSize);
                using FileStream fs1 = File.OpenWrite(fileOutputFullPath);
                {
                    fs1.Write(buffer, 0, buffer.Length);
                    fs1.Close();
                }
                fs.Close();
            }
        }

        /// <summary>
        /// Display headers list
        /// </summary>
        public static void DisplayHeaders(in List<Signature> signatureList)
        {
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signatureList.Count}");
            foreach (Signature signatureRow in signatureList)
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", signatureRow.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", signatureRow.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", signatureRow.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", signatureRow.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(hexValuesToRead: signatureRow.Hex, lengthToPrint: signatureRow.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", signatureRow.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
        }

        public static void DisplayHeadersSearchByExtension(string searchKeyWord, in List<Signature> signatureList)
        {
            int signature1 = signatureList.FindAll(x => x.Name.ToLower().Contains(searchKeyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signatureList.FindAll(x => (x.Name.ToLower().Contains(searchKeyWord.ToLower())))) //Convert all input to lowercase for searching
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(hexValuesToRead: tempSignature.Hex, lengthToPrint: tempSignature.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
        }

        public static void DisplayHeadersSearchByHex(string searchKeyWord, in List<Signature> signatureList)
        {
            int signature1 = signatureList.FindAll(x => x.Hex.ToLower().Contains(searchKeyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signatureList.FindAll(x => (x.Hex.ToLower().Contains(searchKeyWord.ToLower())))) //Convert all input to lowercase for searching
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(hexValuesToRead: tempSignature.Hex, lengthToPrint: tempSignature.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }

        public static void DisplayFileHash(string fileFullPath, string hashType)
        {
            LocalFile localFile = new LocalFile(fileFullPath);
            Console.WriteLine($"\n{hashType} file hash/s -----------------------------------------------------------------------------");
            switch (hashType.ToUpper())
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
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }


    }
}
