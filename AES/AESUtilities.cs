using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AES
{
	public static class AESUtilities
	{
		public static byte[] ConvertStringToBytes(string str)
		{
			return str.ToArray().Select(s => (byte)s).ToArray();
		}

		public static string FormatByteArray(byte[] b)
		{ //http://stackoverflow.com/questions/1149611/getting-slowaes-and-rijndaelmanaged-class-in-net-to-play-together
			var sb1 = new StringBuilder();
			var i = 0;
			for (i = 0; i < b.Length; i++)
			{
				if (i != 0 && i % 16 == 0)
					sb1.Append("\n");
				sb1.Append(System.String.Format("{0:X2} ", b[i]));
			}
			return sb1.ToString();
		}

		public static string FormatByte(byte b)
		{
			var sb1 = new StringBuilder();
			sb1.Append(System.String.Format("{0:X2} ", b));
			
			return sb1.ToString();
		}

	}

	public enum KeySize { Bits128, Bits192, Bits256 };
}
