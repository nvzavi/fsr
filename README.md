# File Signature Resolver (fsr) BETA
A windows console tool that automates some of the manual tasks of reviewing a specified file's signature and overall layout (at a byte level) inorder to ascertain the true nature of the specified file's intentions (example: check if it may be injected and as such, verify if its a possible dropper).
* The following tasks are automated *(based on your selected usage argument)*:  
  * Lookup the file signature of various file types that is contained within the accompanying signature JSON file
  * Quickly Identify the file signature that might by associated with a specified file 
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using an available signature that is contained within the accompanying signature JSON file
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using a custom byte sequence 
  * Quickly carve a byte sequence within a specifed offset range.
  * Generate MD5 / SHA1 / SHA256 / SHA384 / SHA512 hashes of a specified byte.

<h2>Arguments include:</h2>

Argument | Description
------------ | -------------
-h  | Display the help window.
-dh  | Return the complete list of file signatures together with additional signature attributes that is contained within the accompanying signature JSON file.
-dh --search-ext `searchExtKeyWord` | Return a list of file signatures that matched with the specified file extension `searchExtKeyWord` and the extension that is contained within the accompanying signature JSON file.  
-dh --search-hex `searchHexKeyWord` | Return a list of file signatures that matched with the specified byte sequence in hex (base 16) `searchHexKeyWord` and the byte sequence that is contained within the accompanying signature JSON file.  
-ft `fileFullPath` | Return a list possible file signatures that may be associated with the specified file `fileFullPath`. <br/><br/> The output is listed/sorted by degree of probability "high" to "low".
-ft `fileFullPath` `fileOutputFullPath` | Return a list possible file signatures that may be associated with the specified file `fileFullPath`, and the ouput is wrriten to file `fileOutputFullPath`.<br/><br/> If the argument `fileOutputFullPath` already exists then a new file with the same file name together with an appended string '\_fhgen\_{random number}' will be created.<br/><br/> The output is listed/sorted by degree of probability "high" to "low".
-pb `fileFullPath` `searchId` | Patch a specified file's signature `fileFullPath` byte sequence with an available signature ID `searchId` that is associated with a particular file type contained within the accompanying signature JSON file.
-pc `fileFullPath` `hexSequence` `startingHexOffSet` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;| Patch a specified file's signature `fileFullPath` byte sequence at offset `startingHexOffSet` with a custom byte sequence. `hexSequence`.
-cb `fileFullPath` `startingHexOffSet` `endingHexOffSet` `fileOutputFullPath` | Carve out a byte sequence from the specified file `fileFullPath` at starting offset `startingHexOffSet` and ending offset `endingHexOffSet`.  <br/> <br/> The ouput is written to file `fileOutputFullPath`.
-fh `fileFullPath` `hashType` | Generate the required hash value for the specified file `fileFullPath` using the hash algorithm `hashType`.  <br/> <br/> Hashing options for `hashType` include:  md5, sha1, sha256, sha384 and sha512.

<h2> Examples: <h2>
