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

        public static string HexToAscii(string hexValues, int lengthToPrint, bool IgnoreLength) //needs to change , ignorelength must come out
        {
            string ascii = string.Empty;
            string hex = String.Empty;

            if (IgnoreLength == true) //hexvalues is a defined length. no need to substring
            {
                hex = hexValues;
            }
            else if (IgnoreLength == false) { hex = hexValues[..lengthToPrint]; } //substring from 0 to lenght

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
        public static void GetFileType(string args1, string args2, in List<Signature> signature)
        {
            byte[] bytesFile;
            using (FileStream fs = File.OpenRead(args1))//@argFilePath
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

            try
            {
                int columnCount = 9;
                var query = signature.Where(x => header.Contains(x.Hex)); //get all rows where JSON signature matches with a byte sequence in the file

                //add code here to find the original offset if not found at the expected offset

                Console.WriteLine($"\nFile:  {args1}");
                GetMoreFileDetails(args1);

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

                    foreach (var offsetLoc in Offetlocations(sig.Hex, header))//sig.Hex
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

                    string valueAtOffset = ReadCustomByteRange(args1, sig.Offset, Convert.FromHexString(sig.Hex).Length); //get value at expected offset
                    var query1 = signature.Where(x => x.Offset == sig.Offset && x.Hex == valueAtOffset && x.Name == sig.Name); //compare above value to hex value in JSON
                    dataTable.Rows.Add(new object[] { query1.Any() ? "high" : "low",
                sig.Name,
                sig.Offset.ToString(),
                sig.Hex,
                FileOperations.HexToAscii(sig.Hex, sig.Hex.Length, true),
                sig.Mime,
                valueAtOffset,
                FileOperations.HexToAscii(valueAtOffset, valueAtOffset.Length, true),
                locatedPos });//add results to datatable based on above query
                }

                // sort by first column:
                dataTable.DefaultView.Sort = "Col0";
                dataTable = dataTable.DefaultView.ToTable();


                //write output to file
                try
                {
                    if (args2 == "-1") //output to screen
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
                        string fileName = args2;
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
                            sw.WriteLine($"File:  {args1}");
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
                catch (DirectoryNotFoundException)
                {
                    Console.WriteLine("Error:  An invalid path was given in which to output the results!!!");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("Cannot find exact matching header!!!");
                Console.WriteLine("Current Header Information: (Displaying 16 bytes from offset 0)"); //catered for 4 spaces conatined in the header variable
                Console.WriteLine("{0,-15} {1,-64}", "Hexadecimal:", header[..20]); //this is wrong
                Console.WriteLine("{0,-15} {1,-64}", "ASCII:", FileOperations.HexToAscii(header, 20, false)); //this is wrong
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error info:" + ex.Message);
                Console.WriteLine("Press enter to exit....");
                Console.ReadLine();
            }
            finally
            {
                Console.WriteLine("----------------------------------------------------------------------------------------------");
            }
        }

        private static void GetMoreFileDetails(string fullPath)
        {
            LocalFile localFile = new(fullPath);
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

        private static string ReadCustomByteRange(string filePath, int offSet, int lengthToRead) //args1 file args2 offset args3 length to read
        {
            int customSize = lengthToRead;
            byte[] bytesFile = new byte[customSize];

            using (FileStream fs = File.OpenRead(filePath))//@argFilePath
            {
                fs.Position = offSet; //offset to read from
                fs.Read(bytesFile, 0, customSize);
                fs.Close();
            }

            return BitConverter.ToString(bytesFile).Replace("-", "");
        }

        /// <summary>
        /// Patch header from offset 0
        /// </summary> 
        public static void PatchBytes(string args1, string args2, ref List<Signature> signature) //arg1 file arg2 index DONE
        {
            int indexTemp = Convert.ToInt32(args2);

            string revertByte = ReadCustomByteRange(args1, signature[indexTemp - 1].Offset, Convert.FromHexString(signature[indexTemp - 1].Hex).Length); //last arg converts hex to byte then counts length FIX FromHexString see custompatch void

            Console.WriteLine($"Ensure you have backep up file {args1}");
            Console.Write($"Confirm:  Write '{signature[indexTemp - 1].Hex}' byte values matching extension '{signature[indexTemp - 1].Name}' starting at Offset '{signature[indexTemp - 1].Offset}' (type y or n):");

            if (Console.ReadKey().Key == ConsoleKey.Y)
            {
                try
                {
                    using FileStream fs = File.OpenWrite(args1);

                    fs.Position = signature[indexTemp - 1].Offset; //offset JSON IS DECIMAL THIS IS CORRECT ...changed to int64
                    var data = signature[indexTemp - 1].Hex;//.Replace(" ", ""); 
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {signature[indexTemp - 1].Offset} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{args1}\" \"{revertByte}\" \"{signature[indexTemp - 1].Offset}\"");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\nError info:" + ex.Message);
                    Console.WriteLine("Press enter to exit....");
                    Console.ReadLine();
                }
            }
            else
            {
                Environment.Exit(0);
            }
        }

        public static void PatchBytesCustomRange(string args1, string args2, string args3) //args1 file args2 hex args3 offset in hex DONE
        {
            string revertByte = ReadCustomByteRange(args1, Convert.ToInt32(args3, 16), Convert.FromHexString(args2.Replace("0x", "").Replace(" ", "")).Length); //last arg converts hex to byte then counts length

            Console.WriteLine($"Ensure you have backep up file {args1}");
            Console.Write($"Confirm:  Write '{args2}' byte values starting at Offset '{args3}' (type y or n):");
            if (Console.ReadKey().Key == ConsoleKey.Y)
            {
                try
                {
                    using FileStream fs = File.OpenWrite(args1);

                    fs.Position = Convert.ToInt32(args3, 16); //offset WRONG CHECK THE OFFSET IN THE JSON IS IT HEX OR DECIMAL...changed to int64
                    var data = args2.Replace("0x", "").Replace(" ", "");
                    byte[] buffer = Convert.FromHexString(data);
                    fs.Write(buffer, 0, buffer.Length);
                    Console.WriteLine("\nPatch Applied!!!");
                    Console.WriteLine($"Use '{revertByte}' byte values starting at offset {args3} to revert back to the original byte sequence");
                    Console.WriteLine($"Command: -pc \"{args1}\" \"{revertByte}\" \"{args3}\"");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\nError info:" + ex.Message);
                    Console.WriteLine("Press enter to exit....");
                    Console.ReadLine();
                }
            }
            else
            {
                Environment.Exit(0);
            }

        }

        public static void ByteCarver_Offset(string filePath, string startingOffSet, string endingOffSet, string newFilePath) //args1 file args2 offset args3 length to read
        {
            int customSize = Convert.ToInt32(endingOffSet, 16) - Convert.ToInt32(startingOffSet, 16);
            byte[] buffer = new byte[customSize];

            using (FileStream fs = File.OpenRead(filePath))//@argFilePath
            {
                fs.Position = Convert.ToInt32(startingOffSet, 16); //offset to read from
                fs.Read(buffer, 0, customSize);
                using FileStream fs1 = File.OpenWrite(newFilePath);
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
        public static void DisplayHeaders(ref List<Signature> signature)
        {
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature.Count}");
            foreach (Signature signatureRow in signature)
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", signatureRow.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", signatureRow.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", signatureRow.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", signatureRow.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(signatureRow.Hex, signatureRow.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", signatureRow.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
        }

        public static void DisplayHeaders_SearchByExtension(string keyWord, in List<Signature> signature)
        {
            int signature1 = signature.FindAll(x => x.Name.ToLower().Contains(keyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signature.FindAll(x => (x.Name.ToLower().Contains(keyWord.ToLower())))) //Convert all input to lowercase for searching
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
        }

        public static void DisplayHeaders_SearchByHex(string keyWord, in List<Signature> signature)
        {
            int signature1 = signature.FindAll(x => x.Hex.ToLower().Contains(keyWord.ToLower())).Count;
            Console.WriteLine("\n----------------------------------------------------------------------------------------------");
            Console.WriteLine("----------                            FILE HEADERS                                ------------");
            Console.WriteLine("----------------------------------------------------------------------------------------------");
            Console.WriteLine("Note:  Use the ID as FileIndex when pacthing headers with  -pb \"FilePath\" \"FileIndex\"");
            Console.WriteLine($"\nTotal Records:  {signature1}");
            foreach (Signature tempSignature in signature.FindAll(x => (x.Hex.ToLower().Contains(keyWord.ToLower())))) //Convert all input to lowercase for searching
            {
                Console.WriteLine("\n{0,-15} {1,-120}", "ID:", tempSignature.Id);
                Console.WriteLine("{0,-15} {1,-120}", "Extension:", tempSignature.Name);
                Console.WriteLine("{0,-15} {1,-120}", "Offset:", tempSignature.Offset);
                Console.WriteLine("{0,-15} {1,-120}", "Hex:", tempSignature.Hex);
                Console.WriteLine("{0,-15} {1,-120}", "ASCII:", FileOperations.HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true));
                Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
                Console.WriteLine("\n---------------------------------------------");
            }
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }

        public static void DisplayFileHash(string fullPath, string hashType)
        {
            LocalFile localFile = new LocalFile(fullPath);
            Console.WriteLine($"\n{hashType} file hash/s -----------------------------------------------------------------------");
            switch (hashType.ToUpper())
            {
                case "MD5":
                    Console.WriteLine("{0,-15} {1,-64}", "MD5:", localFile.GetMD5Hash());
                    break;
                case "SHA1":
                    Console.WriteLine("{0,-15} {1,-64}", "SHA1:", localFile.GetSHA1Hash());
                    break;
                case "SHA256":
                    Console.WriteLine("{0,-15} {1,-64}", "SHA256:", localFile.GetSHA256Hash());
                    break;
                case "SHA384":
                    Console.WriteLine("{0,-15} {1,-64}", "SHA384:", localFile.GetSHA384Hash());
                    break;
                case "SHA512":
                    Console.WriteLine("{0,-15} {1,-64}", "SHA512:", localFile.GetSHA512Hash());
                    break;
                case "ALL":
                    Console.WriteLine("{0,-15} {1,-64}", "MD5:", localFile.GetMD5Hash());
                    Console.WriteLine("{0,-15} {1,-64}", "SHA1:", localFile.GetSHA1Hash());
                    Console.WriteLine("{0,-15} {1,-64}", "SHA256:", localFile.GetSHA256Hash());
                    Console.WriteLine("{0,-15} {1,-64}", "SHA384:", localFile.GetSHA384Hash());
                    Console.WriteLine("{0,-15} {1,-64}", "SHA512:", localFile.GetSHA512Hash());
                    break;
                default:
                    break;
            }
            Console.WriteLine("----------------------------------------------------------------------------------------------");
        }


    }
}
