using System;
using System.Collections;
using System.Linq;
using System.Collections.Generic;

namespace AES
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.ForegroundColor = ConsoleColor.Red;
			Console.WriteLine("AES\n--------------------");
			Console.ResetColor();

			RunCipherExample();
			Run128();
			Run192();
			Run256();

			Console.ReadLine();
		}

		public static void RunCipherExample()
		{
			var plaintext = new byte[16] { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
			var cipherKey = new byte[16] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

			var keySize = KeySize.Bits128;
			var aesMachine = new AESMachine(keySize, cipherKey);
			var cipherText = aesMachine.Encrypt(plaintext);
			var plainTextAgain = aesMachine.Decrypt(cipherText);

			PrintResults(keySize, plaintext, cipherText, plainTextAgain);
		}

		public static void Run128()
		{
			var plaintext = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
			var cipherKey = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

			var keySize = KeySize.Bits128;
			var aesMachine = new AESMachine(keySize, cipherKey);
			var cipherText = aesMachine.Encrypt(plaintext);
			var plainTextAgain = aesMachine.Decrypt(cipherText);

			PrintResults(keySize, plaintext, cipherText, plainTextAgain);
		}

		public static void Run192()
		{

			var plaintext = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }; 
			var cipherKey = new byte[24] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

			var keySize = KeySize.Bits192;
			var aesMachine = new AESMachine(keySize, cipherKey);
			var cipherText = aesMachine.Encrypt(plaintext);
			var plainTextAgain = aesMachine.Decrypt(cipherText);

			PrintResults(keySize, plaintext, cipherText, plainTextAgain);
		}

		public static void Run256()
		{
			var plaintext = new byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
			var cipherKey = new byte[32] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

			var keySize = KeySize.Bits256;
			var aesMachine = new AESMachine(keySize, cipherKey);
			var cipherText = aesMachine.Encrypt(plaintext);
			var plainTextAgain = aesMachine.Decrypt(cipherText);

			PrintResults(keySize, plaintext, cipherText, plainTextAgain);
		}

		public static void PrintResults(KeySize keySize, byte[] pt, byte[] ct, byte[] pt2)
		{
			Console.ForegroundColor = ConsoleColor.Cyan;
			Console.WriteLine("Key Size:   {0}", keySize);
			Console.ResetColor();
			Console.WriteLine("PlainText:  {0}", AESUtilities.FormatByteArray(pt));
			Console.WriteLine("CipherText: {0}", AESUtilities.FormatByteArray(ct));
			Console.WriteLine("PlainText:  {0}", AESUtilities.FormatByteArray(pt2));
			Console.WriteLine();
		}
	}
}
