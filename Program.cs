
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
FileOperations.LoadJson( signatureListFilePath: signatureFilePath, signatureList: ref signature);


//DisplayHeaders(ref signature);//Display all headers
//DisplayHeaders_SearchByExtension("docx", in signature);
//DisplayHeaders_SearchByHex("44", in signature);
//FileOperations.GetFileType("C:\\Users\\Admin\\Desktop\\text.xlsx",
//    in signature); //in is cannot be changed

//FileOperations.GetFileType("C:\\Users\\Admin\\Desktop\\text.xlsx", in signature, "C:\\out2.txt"); //in is cannot be changed
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
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"fileFullPath\"", "Get the file type");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-ft (file type)", "-ft \"fileFullPath\" \"fileOutputFullPath\"", "Get the file type and write results to file");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "Displays current header if no type is found");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-pb (patch byte/s)", "-pb \"fileFullPath\" \"searchId\"", "Patch the header at offset specified in JSON file");
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
    case "-ft": //add validation to check if file is a path actual file e.g must not --s
        if (args.Length==2) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature); }
        else if (args.Length== 3) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature, fileOutputFullPath: args[2]); }
        else { goto default; }
        break;
    case "-pb":
        if (args.Length == 3)
        {
            //Patch the file with the selected header from the header list
            FileOperations.PatchBytes(fileFullPath: args[1], searchId: Convert.ToInt32(args[2]), signatureList: in signature);
        }
        else { goto default; }
        break;
    case "-pc": 
        if (args.Length==4)
        {
            //Patch the file with the selected header from the header list
            FileOperations.PatchBytesCustomRange(fileFullPath: args[1], hexSequence: args[2], startingHexOffSet: args[3]);
        }
        else { goto default; }     
        break;
    case "-cb": 
        if (args.Length == 5)
        {
            //Read bytes at offset and return hex and ASCII values
            FileOperations.ByteCarverByOffsets(fileFullPath: args[1], startingHexOffSet: args[2], endingHexOffSet: args[3], fileOutputFullPath: args[4]); 
        }
        else { goto default; }
        break;
    case "-dh":
        //Display headers list
        if (args.Length == 1)
        {
            FileOperations.DisplayHeaders(signatureList: in signature);//Display all headers
        }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { FileOperations.DisplayHeadersSearchByExtension(searchKeyWord: args[2], signatureList: in signature); } //Serach by type }
            else if (args[1] == "--search-hex") { FileOperations.DisplayHeadersSearchByHex(searchKeyWord: args[2], signatureList: in signature); } //Serach by hex }
        }
        else { goto default; }
        break;
    case "-fh":
        if (args.Length==3)
        {
            if (File.Exists(args[1]))
            {
                FileOperations.DisplayFileHash(fileFullPath: args[1], hashType: args[2]);
            }
            else { Console.WriteLine("Error:  File to analyse was not found!!!"); }
        }
        else { goto default; }
        break;
    default:
        Console.WriteLine("Error:  Please enter the required commands/arguments!!! \nUse command fh_res -h to view the help window");
        break;
}