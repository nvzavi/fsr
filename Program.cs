﻿
using System;
using System.Collections;
using System.Collections.Concurrent;
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


//really cool extensions.json file is used as my reference database and it was retreived from https://github.com/qti3e (Specific gist https://gist.github.com/Qti3e/6341245314bf3513abb080677cd1c93b)
string signatureFilePath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + "\\extensions.json";
List<Signature> signature = new();
FileOperations.LoadJson(signatureListFilePath: signatureFilePath, signatureList: ref signature);

switch (args[0])
{
    case "-h":
        Console.WriteLine("\n------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("-------------------------                              FILE SIGNATURE RESOLVER v1.0  (BETA)                                ---------------------");
        Console.WriteLine("-------------------------                                                    with added patching/carving/hashing features  ---------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("***NOTE:  Use at your own risk.  Patching header bytes can render the file unusable.  Always backup files prior to patching the headers. ");
        Console.WriteLine("\n{0,-25} {1,-60} {2,-50}", "Command/s", "Usage", "Notes");
        Console.WriteLine("------------------------------------------------------------------------------------------------------------------------------------------------");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "-dh (display header)", "-dh", "Display all file signatures that are contained within the");
        Console.WriteLine("{0,-25} {1,-60} {2,-50}", "", "", "accompanying database (JSON file).  Use | more for paging");
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
    case "-ft"://file type
        if (args.Length==2) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature); }
        else if (args.Length== 3) { FileOperations.GetFileType(fileFullPath: args[1], signatureList: in signature, fileOutputFullPath: args[2]); }
        else { goto default; }
        break;
    case "-pb"://patch  byte/s
        if (args.Length == 3)
        {
            FileOperations.PatchBytes(fileFullPath: args[1], searchId: Convert.ToInt32(args[2]), signatureList: in signature);
        }
        else { goto default; }
        break;
    case "-pc"://patch custom byte/s
        if (args.Length==4)
        {
            FileOperations.PatchBytesCustomRange(fileFullPath: args[1], hexSequence: args[2], startingHexOffSet: args[3]);
        }
        else { goto default; }     
        break;
    case "-cb"://carve byte/s  
        if (args.Length == 5)
        {
            FileOperations.ByteCarverByOffsets(fileFullPath: args[1], startingHexOffSet: args[2], endingHexOffSet: args[3], fileOutputFullPath: args[4]); 
        }
        else { goto default; }
        break;
    case "-dh"://display header
        if (args.Length == 1) { FileOperations.DisplayHeaders(signatureList: in signature); }
        else if (args.Length == 3)
        {
            if (args[1] == "--search-ext") { FileOperations.DisplayHeadersSearchByExtension(searchExtKeyWord: args[2], signatureList: in signature); } 
            else if (args[1] == "--search-hex") { FileOperations.DisplayHeadersSearchByHex(searchHexKeyWord: args[2], signatureList: in signature); } 
            else { goto default; }
        }
        else { goto default; }
        break;
    case "-fh"://file hash
        if (args.Length==3)
        {
            FileOperations.DisplayFileHash(fileFullPath: args[1], hashType: args[2]);
        }
        else { goto default; }
        break;
    default:
        Console.WriteLine("Error: Please enter the required commands/arguments!!! \nUse command fh_res -h to view the help window");
        break;
}