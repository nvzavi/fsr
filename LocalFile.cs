using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;

namespace fh_res
{
    class LocalFile 
    {
        public string FullPath { get; set; }
        public string Name { get; }
        public long FileSize { get; }
        public DateTime CreatedDate { get; }
        public DateTime LastModifiedDate { get; }
        public DateTime LastAccessed { get; }

        public string MD5HashValue { get; }
        public string Sha1HashValue { get; }
        public string Sha256HashValue { get; }
        public string Sha384HashValue { get; }
        public string Sha512HashValue { get; }

        public LocalFile(string fullPath)
        {
            FullPath = fullPath;
            Name = GetFileName();
            FileSize = GetFileSize();
            CreatedDate = GetCreatedDate();
            LastModifiedDate = GetLastModifiedDate();
            LastAccessed = GetLastAccessed();
            MD5HashValue = GetMD5Hash();
            Sha1HashValue = GetSHA1Hash();
            Sha256HashValue = GetSHA256Hash();
            Sha384HashValue = GetSHA384Hash();
            Sha512HashValue = GetSHA512Hash();
        }
        private long GetFileSize()
        {
            long fileSize = new System.IO.FileInfo(FullPath).Length; //possible error here NULL values
            return fileSize;
        }

        private DateTime GetCreatedDate()
        {
            DateTime fileCreatedDate = new System.IO.FileInfo(FullPath).CreationTime; //possible error here NULL values
            return fileCreatedDate;
        }
        private DateTime GetLastModifiedDate()
        {
            DateTime fileLastModifiedDate = new System.IO.FileInfo(FullPath).LastWriteTime; //possible error here NULL values
            return fileLastModifiedDate;
        }
        private DateTime GetLastAccessed()
        {
            DateTime fileLastAccessed = new System.IO.FileInfo(FullPath).LastAccessTime; //possible error here NULL values
            return fileLastAccessed;
        }

        private string GetFileName()
        {
            return Path.GetFileName(FullPath);
        }

        private string GetMD5Hash()
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(FullPath))
                {
                    return BitConverter.ToString(md5.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

        private string GetSHA1Hash()
        {
            using (var sha = SHA1.Create())
            {
                using (var stream = File.OpenRead(FullPath))
                {
                    return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

        private string GetSHA256Hash()
        {
            using (var sha = SHA256.Create())
            {
                using (var stream = File.OpenRead(FullPath))
                {
                    return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

        private string GetSHA384Hash()
        {
            using (var sha = SHA384.Create())
            {
                using (var stream = File.OpenRead(FullPath))
                {
                    return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

        private string GetSHA512Hash()
        {
            using (var sha = SHA512.Create())
            {
                using (var stream = File.OpenRead(FullPath))
                {
                    return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty);
                }
            }
        }

    }
}
