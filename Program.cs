
using System;
using System.Collections;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.IO.Enumeration;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using fh_res;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


//Declare full path to signature JSON file
//JSON retrieved from https://github.com/qti3e renamed file to signatures.json
string signatureFilePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\signatures.json";
//update
//Declare list type signature into which the magic contents will be loaded
List<Signature> signature = new();

//Load magic text contents into signature object
LoadJson(signatureFilePath, ref signature); //ref used as it can be modified


//DisplayHeaders(ref signature);//Display all headers
//DisplayHeaders_SearchByExtension("docx", in signature);
//DisplayHeaders_SearchByHex("44", in signature);
//GetFileType("C:\\Users\\Admin\\Documents\\Win10_1703_English_x64.iso", "-1",
//    in signature); //in is cannot be changed

//GetFileType("C:\\Users\\Admin\\Documents\\Win10_1703_English_x64.iso", "C:\\Users\\Admin\\Desktop1\\out.txt",
//    in signature); //in is cannot be changed
//DisplayHeaders_SearchByExtension("lha", ref signature); //id 16 has na offset of 2
//PatchBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "16", ref signature);4d5a
//byte[] temp = Convert.FromHexString("0x4d 0x5a".Replace("0x","").Replace(" ",""));
//PatchBytesCustomRange("C:\\Users\\Admin\\Desktop\\test123.xlsx", "7468", "0x4f0");
//ReadCustomByteRange("C:\\Users\\Admin\\Desktop\\text.xlsx", "2", "3");
//ReadBytes("C:\\Users\\Admin\\Desktop\\text.xlsx", "384", "19");
//ReadCustomByteRange_Offset("C:\\Users\\Admin\\Desktop\\text.xlsx", "0x180", "0x193", "C:\\Users\\Admin\\Desktop\\rcro1.txt");
//DisplayFileHash("C:\\Users\\Admin\\Desktop\\test123.xlsx", "all");
switch (args[0])
{
    case "-h":
        Console.WriteLine("\n------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("-------------------------                                 FILE HEADER RESOLVER v1.0  (BETA)                                ---------------------");
        Console.WriteLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
        Console.WriteLine("\n{0,-25} {1,-60} {2,-50}", "Command/s", "Usage", "Notes");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh (display header)", "-dh", "Return all stored headers.  Use | more for paging");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-ext", "-dh --search-ext \"keyword\"", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"if\" returns GIF");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh --search-hex", "-dh --search-hex \"hex value\\s\"", "Must NOT be space seperated e.g. \"4D5A\"");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Case-insensitive search");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Contained within search e.g. \"4D\" returns 42 4D");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"FilePath\"", "Get the file type");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"FilePath\" \"NewFilePath\"", "Get the file type and write results to file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pb (patch byte/s)", "-pb \"FilePath\" \"FileIndex\"", "Patch the header at offset specified in JSON file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Use the -dh command to get the file index");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pc (patch custom)", "-pc \"FilePath\" \"hex value\\s\" \"offset\"", "Apply custom patch starting at specified offset");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "NOTE:  Use at your own risk.  Always backup files first.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-cb (carve byte/s)", "-cb \"FilePath\" \"Start Offset\" \"End Offset\" \"NewFilePath\"", "Carve out bytes from file and save ouput to a new file.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-fh (file hash)", "-fh \"FilePath\" \"Hash Type\"", "Generate file hashes.");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "\"Hash Type\" options: MD5, SHA1, SHA256, SHA384, SHA512");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "\"Hash Type\" additional option: \"ALL\" will generate all");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "file hashes as specified above");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        break;
    case "-ft":
        if (args.Length == 2) //this is write to screen
        {
            if (File.Exists(args[1]))
            {
                GetFileType(args[1], "-1", in signature); //arg[1]:  File path to get type of, arg[2]:  -1 denoting an output to screen
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else if (args.Length == 3) //this is a write to file
        {
            if (File.Exists(args[1]))
            {
                if (Directory.Exists(Path.GetDirectoryName(args[2])))
                {
                    GetFileType(args[1], args[2], in signature); //arg[1]:  File path to get type of, arg[2]:  list of headers //in used as must not be modified
                }
                else { Console.WriteLine("Error:  An invalid path was given in which to output the results!!!"); }
                
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage (Option A):  -pb \"FilePath\" ");
            Console.WriteLine("Usage (Option B):  -pb \"FilePath\" \"NewFilePath\"");
        }
        break;
    case "-pb":
        if (args.Length == 3)
        {
            //Patch the file with the selected header from the header list
            PatchBytes(args[1], args[2], ref signature);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -pb \"FilePath\" \"FileIndex\"");
        }
        break;
    case "-pc": //DONE
        if (args.Length==4)
        {
            //Patch the file with the selected header from the header list
            PatchBytesCustomRange(args[1], args[2], args[3]);//arg[1]:  File path of file to patch, arg[2]:  Index of header to patch with, arg[3]:  list of headers
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -pc \"FilePath\" \"hex value\\s\" \"offset\"");
        }     
        break;
    case "-cb": //DONE
        if (args.Length == 5)
        {
            //Read bytes at offset and return hex and ASCII values
            byteCarver_Offset(args[1], args[2], args[3], args[4]); //arg[1]: FilePath arg[2]: Offset  arg[3]: Length to read
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -cb \"FilePath\" \"Start Offset\" \"End Offset\" \"NewFilePath\"");
        }
        break;
    case "-dh":
        //Display headers list
        if (args.Length == 1)
        {
            DisplayHeaders(ref signature);//Display all headers
        }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { DisplayHeaders_SearchByExtension(args[2], in signature); } //Serach by type }
            else if (args[1] == "--search-hex") { DisplayHeaders_SearchByHex(args[2], in signature); } //Serach by hex }
        }
        break;
    case "-fh":
        if (args.Length==3)
        {
            if (File.Exists(args[1]))
            {
                DisplayFileHash(args[1],args[2]);
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else
        {
            Console.WriteLine("Error:  Please enter the required arguments!!!");
            Console.WriteLine("Usage:  -fh \"FilePath\" \"Hash Type\"");
        }
        break;
    default:
        Console.WriteLine("Error:  Unknown command!!!");
        Console.WriteLine("Press enter to exit....");
        Console.ReadLine();
        break;
}

static string HexToAscii(string hexValues, int lengthToPrint, bool IgnoreLength) //needs to change , ignorelength must come out
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
/// Patch header from offset 0
/// </summary> 
static void PatchBytes(string args1, string args2, ref List<Signature> signature) //arg1 file arg2 index DONE
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

static void PatchBytesCustomRange(string args1, string args2, string args3) //args1 file args2 hex args3 offset in hex DONE
{
    string revertByte = ReadCustomByteRange(args1, Convert.ToInt32(args3,16), Convert.FromHexString(args2.Replace("0x", "").Replace(" ", "")).Length); //last arg converts hex to byte then counts length

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

/// <summary>
/// Display headers list
/// </summary>
static void DisplayHeaders(ref List<Signature> signature)
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
        Console.WriteLine("{0,-15} {1,-120}", "ASCII:", HexToAscii(signatureRow.Hex, signatureRow.Hex.Length, true));
        Console.WriteLine("{0,-15} {1,-120}", "MIME:", signatureRow.Mime);
        Console.WriteLine("\n---------------------------------------------");
    }
}

static void DisplayHeaders_SearchByExtension(string keyWord, in List<Signature> signature)
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
        Console.WriteLine("{0,-15} {1,-120}", "ASCII:", HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true));
        Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
        Console.WriteLine("\n---------------------------------------------");
    }
}

static void DisplayHeaders_SearchByHex(string keyWord, in List<Signature> signature)
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
        Console.WriteLine("{0,-15} {1,-120}", "ASCII:", HexToAscii(tempSignature.Hex, tempSignature.Hex.Length, true));
        Console.WriteLine("{0,-15} {1,-120}", "MIME:", tempSignature.Mime);
        Console.WriteLine("\n---------------------------------------------");
    }
    Console.WriteLine("----------------------------------------------------------------------------------------------");
}

static void GetMoreFileDetails(string fullPath)
{
    LocalFile localFile = new LocalFile(fullPath);
    Console.WriteLine("\nFile Attributes --------------------------------------------------------------------------------");
    Console.WriteLine("{0,-15} {1,-64}", "File Name:" , localFile.Name);
    Console.WriteLine("{0,-15} {1,-64}", "File Size:" , localFile.FileSize + " bytes");
    Console.WriteLine("{0,-15} {1,-64}", "Created Date:" , localFile.CreatedDate );
    Console.WriteLine("{0,-15} {1,-64}", "Accessed Date:" , localFile.LastAccessed );
    Console.WriteLine("{0,-15} {1,-64}", "Modified Date:", localFile.LastModifiedDate ); 
    //Console.WriteLine("{0,-15} {1,-64}", "MD5:", localFile.MD5HashValue);
    //Console.WriteLine("{0,-15} {1,-64}", "SHA1:" , localFile.Sha1HashValue);
    //Console.WriteLine("{0,-15} {1,-64}", "SHA256:" , localFile.Sha256HashValue);
    //Console.WriteLine("{0,-15} {1,-64}", "SHA384:" , localFile.Sha384HashValue);
    //Console.WriteLine("{0,-15} {1,-64}", "SHA512:" , localFile.Sha512HashValue);
    Console.WriteLine("----------------------------------------------------------------------------------------------");
}

static void DisplayFileHash(string fullPath, string hashType)
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

static string ReadCustomByteRange(string filePath, int offSet, int lengthToRead) //args1 file args2 offset args3 length to read
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

static void byteCarver_Offset(string filePath, string startingOffSet, string endingOffSet, string newFilePath) //args1 file args2 offset args3 length to read
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

static IEnumerable Offetlocations(string searchTerm, string searchStr)
{
    int searchPos = 0;
    int retVal= searchStr.IndexOf(searchTerm, searchPos);
    while (retVal!=-1)
    {
        yield return retVal;
        searchPos = retVal + searchTerm.Length;
        retVal = searchStr.IndexOf(searchTerm, searchPos); 
    }
}

/// <summary>
/// Display File Type
/// </summary>
static void GetFileType(string args1, string args2, in List<Signature> signature)
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

        for (int i = 0; i <= columnCount-1; i++)
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
            int posValue=0;

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
                else if (posCounter<=5)
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
                HexToAscii(sig.Hex, sig.Hex.Length, true),
                sig.Mime, 
                valueAtOffset, 
                HexToAscii(valueAtOffset, valueAtOffset.Length, true), 
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
        Console.WriteLine("{0,-15} {1,-64}", "ASCII:", HexToAscii(header, 20, false)); //this is wrong
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

static void LoadJson(string signatureListFilePath, ref List<Signature> signatureList)
{
    List<StagingSignature> stagingSignature = new();

    using (StreamReader r = new(signatureListFilePath))
    {
        string json = r.ReadToEnd(); //read the JSON file
        var jo = JObject.Parse(json); //initialise an object to iterate through the nodes

        foreach (var kv in jo)
        {
            if (kv.Value!=null)
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
                string hexValue = val.Substring(val.IndexOf(',')+1); //substring(2)
                signatureList.Add(new Signature() { 
                    Id = stagingCounter, 
                    Name = signs.Name, 
                    Offset = offset, 
                    Hex  = hexValue, 
                    Mime = signs.Mime });
                stagingCounter++;
            }
        }
        r.Close();
    }
}
