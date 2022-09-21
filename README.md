# File Signature Resolver (fsr) BETA
A windows console tool that automates some of the manual tasks of reviewing a specified file's signature and overall layout (at a byte level) inorder to ascertain the true nature of the specified file's intentions (example: check if it may be injected and as such, verify if its a possible dropper).
* The following tasks are automated *(based on your selected usage argument)*:  
  * Lookup the file signature of various file types that is contained with the accompanying signature JSON file
  * Quickly Identify the file signature that might by associated with a specified file 
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using an avaiable signature that is contained with the accompanying signature JSON file
  * Quickly patch a file's signature byte sequence that may be suspected of file signature tampering using a custom byte sequence 
  * Generate MD5 / SHA1 / SHA256 / SHA384 / SHA512 hashes of a specified byte.

<h2>Arguments include:</h2>

Argument | Description
------------ | -------------
<sub>-h<sub>  | xxx
<sub>-dh<sub>  | xxx
<sub>-dh --search-ext `searchExtKeyWord`<sub> | xxx
<sub>-dh --search-hex `searchHexKeyWord`<sub> | xxx
<sub>-ft `fileFullPath`<sub> | xxx
<sub>-ft `fileFullPath` `fileOutputFullPath`<sub> | newfile ending '_fhgen_random number' is created is file exists
<sub>-pb `fileFullPath` `searchId`<sub> | xxx
<sub>-pc `fileFullPath` `hexSequence` `startingHexOffSet`<sub> | xxx
<sub>-cb `fileFullPath` `startingHexOffSet` `endingHexOffSet` `fileOutputFullPath`<sub> | xxx
<sub>-fh `fileFullPath` `hashType`<sub> | xxx
