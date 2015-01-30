using System;
using System.Collections.Generic;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace supergenpass
{
    class Crypto
    {
        private List<String> algorithms;
        private String activeAlgorithm;

        public String ActiveAlgorithm
        {
            get { return this.activeAlgorithm; }
            set {
                if (algorithms.IndexOf(value) >= 0)
                {
                    this.activeAlgorithm = value;
                }
                else
                {
                    throw new Exception("Invalid Algorithm Provided:" + value);
                }
            }
        }

        public Crypto()
        {
            // Define possible algorithms
            this.algorithms.Add(HashAlgorithmNames.Md5);
            this.algorithms.Add(HashAlgorithmNames.Sha512);

            this.ActiveAlgorithm = HashAlgorithmNames.Md5;
        }

        public String getHash(String input)
        {
            String hash = "";
            HashAlgorithmProvider algorithmProv = HashAlgorithmProvider.OpenAlgorithm(this.ActiveAlgorithm);
            CryptographicHash hashObject = algorithmProv.CreateHash();

            IBuffer bufferedMessage = CryptographicBuffer.ConvertStringToBinary(input, BinaryStringEncoding.Utf16BE);
            hashObject.Append(bufferedMessage);
            IBuffer bufferedHash = hashObject.GetValueAndReset();

            hash = CryptographicBuffer.EncodeToBase64String(bufferedHash);

            return hash;
        }
    }
}
