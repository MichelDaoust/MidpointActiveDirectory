/**
 *
 * Copyright (c) 2013 Salford Software Ltd All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Linq;


// Author: Matthew Wright
namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    static class Encryptor
    {
        /// <summary>
        /// This tag marks the start of the encrypted password string in encryptor stdout.
        /// </summary>
        const string startEncryptionTag = "START ENCRYPTION";
        /// <summary>
        /// This tag marks the end of the encrypted password string in encryptor stdout.
        /// </summary>
        const string endEncryptionTag = "END ENCRYPTION";
        /// <summary>
        /// This tag marks the start of the decrypted password string in encryptor stdout.
        /// </summary>
        const string startDecryptionTag = "START DECRYPTION";
        /// <summary>
        /// This tag marks the end of the decrypted password string in encryptor stdout.
        /// </summary>
        const string endDecryptionTag = "END DECRYPTION";

        /// <summary>
        /// Encrypts the plaintexts and returns the ciphertext
        /// </summary>
        /// <param name="plaintext">Plaintext to encrypt.</param>
        /// <returns>The associated ciphertext.</returns>
        public static string Encrypt(string plaintext)
        {

            return StringCipher.Encrypt(plaintext, "Super Key");

            //            return RunEncryptorFile(true, plaintext);
        }

        /// <summary>
        /// Decrypts the ciphertext and returns the plaintext.
        /// </summary>
        /// <param name="ciphertext">Ciphertext to decrypt.</param>
        /// <returns>The associated plaintext string.</returns>
        public static string Decrypt(string ciphertext)
        {
            return StringCipher.Decrypt(ciphertext, "Super Key");

            //            return RunEncryptorFile(false, ciphertext);
        }

/*
        private static string RunEncryptorFile(bool encrypting, string inputString)
        {
            string startTag = (encrypting) ? startEncryptionTag : startEncryptionTag;
            string endTag = (encrypting) ? endEncryptionTag : endEncryptionTag;

            //Set mode - must have space after e/d to separate from next argument
            string mode = (encrypting) ? "e " : "d ";
            string newPassword = "";

            var psi = new ProcessStartInfo
            {
                FileName = Constants.encryptorPath,
                Arguments = mode + inputString,
                UseShellExecute = false,
                RedirectStandardOutput = true,
            };

            var process = Process.Start(psi);
            if (process.WaitForExit((int)TimeSpan.FromSeconds(10).TotalMilliseconds))
            {
                var result = process.StandardOutput.ReadToEnd();

                // Strip the start and end tags from decrypted password string
                string[] stringLines = result.Split(new char[] { '\n' });
                bool start = false;
                foreach (string line in stringLines)
                {
                    string trimmedLine = line.TrimEnd(new char[] { '\r', '\n' });

                    if (start)
                    {
                        if (trimmedLine == endTag)
                        {
                            // Found end tag - stop parsing decrypted string
                            // Don't want to add end tag to decrypted string
                            Console.WriteLine("endtag");
                            break;
                        }
                        else
                        {
                            // If the line is between start and end tags then append it to decrypted string
                            newPassword += trimmedLine;
                            Console.WriteLine("running encrypt: '" + newPassword + "'");
                        }
                    }
                    else if (trimmedLine == startTag)
                    {
                        // Found start tag - must check this AFTER attempting to add to decrypted string 
                        // Otherwise the start tag would be added to the decrypted string
                        start = true;
                        Console.WriteLine("start tag");
                    }
                }
            }
            Console.WriteLine("return encrypt: '" + newPassword + "'");

            return newPassword;
        }
*/
    }



    public static class StringCipher
    {
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }


}
