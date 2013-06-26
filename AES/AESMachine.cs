using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;

namespace AES
{
	/// <summary>
	/// Implements AES
	/// Allows for encryption and decryption using AES guidelines
	/// </summary>
	public class AESMachine
	{
		#region Properties
		readonly byte[][] _cipherKey;
		byte[][] _keySchedule;
		readonly KeySize _keyBitSize;

		byte[,] _sbox, _isbox;
		byte[][] _rcon;
		byte[][] _state;

		int _blockSize, _keySize, _numRounds;

		const int SBOX_LENGTH = 16;
		BitArray _1B = new BitArray(new byte[1] { 0x1b }); 
		#endregion

		#region Constructor
		public AESMachine(KeySize keylength, byte[] cipherKey)
		{
			_keyBitSize = keylength;
			SetNbNkNr(_keyBitSize);

			// Initialize Objects if needed
			if (_sbox == null) _sbox = InitializeSbox();
			if (_isbox == null) _isbox = InitializeInvSbox();
			if (_rcon == null) _rcon = InitializeRCon();

			_cipherKey = Convert1DArrayTo2D(cipherKey, _keySize, 4);
			KeyExpansion(_cipherKey);
		}
		#endregion

		#region Public Methods
		/// <summary>
		/// Encrypts the specified plain text.
		/// </summary>
		/// <param name="plainText">The plain text.</param>
		/// <returns>byte[] of ciphertext</returns>
		public byte[] Encrypt(byte[] plainText)
		{
			_state = InitializeState(plainText);

			// Run through the encryption steps
			_state = AddRoundKey(_state, 0);
			var curRound = 1;
			for (; curRound <= _numRounds - 1; curRound++)
			{
				_state = SubBytes(_state);
				_state = ShiftRows(_state);
				_state = MixColumns(_state);
				_state = AddRoundKey(_state, curRound);
			}
			_state = SubBytes(_state);
			_state = ShiftRows(_state);
			_state = AddRoundKey(_state, curRound);

			// Convert and return the ciphertext
			return Convert2DArrayTo1D(_state);
		}
		/// <summary>
		/// Decrypts the specified cipher text.
		/// </summary>
		/// <param name="cipherText">The cipher text.</param>
		/// <returns>byte[] of unencrypted plaintext</returns>
		public byte[] Decrypt(byte[] cipherText)
		{
			_state = Convert1DArrayTo2D(cipherText, 4, 4);

			var curRound = _numRounds;
			_state = AddRoundKey(_state, curRound--);
			_state = ShiftRows(_state, false);
			_state = SubBytes(_state, false);

			for (; curRound > 0; curRound--)
			{
				_state = AddRoundKey(_state, curRound);
				_state = MixColumns(_state, false);
				_state = ShiftRows(_state, false);
				_state = SubBytes(_state, false);
			}
			_state = AddRoundKey(_state, curRound);

			return Convert2DArrayTo1D(_state);
		}
		#endregion

		#region Private Methods
		#region AES Methods
		private byte[] SubBytes(byte[] state, bool encrypt = true)
		{
			byte[,] box = encrypt ? _sbox : _isbox;

			for (var i = 0; i < state.Length; i++)
				state[i] = box[state[i] >> 4, state[i] & 0x0f];

			return state;
		}
		private byte[][] SubBytes(byte[][] state, bool encrypt = true)
		{
			for (var i = 0; i < state.Length; i++)
				state[i] = SubBytes(state[i], encrypt);

			return state;
		}
		private byte[][] ShiftRows(byte[][] state, bool encrypt = true)
		{
			if (encrypt)
			{
				state = ShiftRowToTheLeft(state, 1);
				state = ShiftRowToTheLeft(state, 2);
				state = ShiftRowToTheLeft(state, 3);
			}
			else 
			{
				state = ShiftRowToTheRight(state, 1);
				state = ShiftRowToTheRight(state, 2);
				state = ShiftRowToTheRight(state, 3);
			}
			return state;
		}
		private byte[][] MixColumns(byte[][] state, bool encrypt = true)
		{
			var ffMatrix = encrypt ?
				   new byte[4][] {  new byte[4] { 0x02, 0x03, 0x01, 0x01 }, 
									new byte[4] { 0x01, 0x02, 0x03, 0x01 },
									new byte[4] { 0x01, 0x01, 0x02, 0x03 },
									new byte[4] { 0x03, 0x01, 0x01, 0x02 } } :
					new byte[4][] { new byte[4] { 0x0e, 0x0b, 0x0d, 0x09 }, 
									new byte[4] { 0x09, 0x0e, 0x0b, 0x0d },
									new byte[4] { 0x0d, 0x09, 0x0e, 0x0b },
									new byte[4] { 0x0b, 0x0d, 0x09, 0x0e } };

			byte[][] temp = new byte[4][];
			for (int r = 0; r < 4; ++r)
			{
				temp[r] = new byte[4];
				for (int c = 0; c < 4; ++c)
				{
					temp[r][c] = state[r][c];
				}
			}

			for (int r = 0; r < 4; ++r)
			{
				state[r][0] = (byte)((int)ffmultiply(temp[r][0], ffMatrix[0][0]) ^
										   (int)ffmultiply(temp[r][1], ffMatrix[0][1]) ^
										   (int)ffmultiply(temp[r][2], ffMatrix[0][2]) ^
										   (int)ffmultiply(temp[r][3], ffMatrix[0][3]));

				state[r][1] = (byte)((int)ffmultiply(temp[r][0], ffMatrix[1][0]) ^
										   (int)ffmultiply(temp[r][1], ffMatrix[1][1]) ^
										   (int)ffmultiply(temp[r][2], ffMatrix[1][2]) ^
										   (int)ffmultiply(temp[r][3], ffMatrix[1][3]));

				state[r][2] = (byte)((int)ffmultiply(temp[r][0], ffMatrix[2][0]) ^
										   (int)ffmultiply(temp[r][1], ffMatrix[2][1]) ^
										   (int)ffmultiply(temp[r][2], ffMatrix[2][2]) ^
										   (int)ffmultiply(temp[r][3], ffMatrix[2][3]));

				state[r][3] = (byte)((int)ffmultiply(temp[r][0], ffMatrix[3][0]) ^
										   (int)ffmultiply(temp[r][1], ffMatrix[3][1]) ^
										   (int)ffmultiply(temp[r][2], ffMatrix[3][2]) ^
										   (int)ffmultiply(temp[r][3], ffMatrix[3][3]));
			}
			return state;
		}
		private byte[][] AddRoundKey(byte[][] state, int round)
		{
			for (var r = 0; r < 4; ++r)
				for (var c = 0; c < 4; ++c)
					state[r][c] = (byte)((int)state[r][c] ^ (int)_keySchedule[(round * 4) + r][c]);

			return state;
		}
		private void KeyExpansion(byte[][] cipherKey)
		{
			_keySchedule = new byte[_blockSize * (_numRounds + 1)][];

			for (var row = 0; row < _keySize; ++row)
			{
				_keySchedule[row] = new byte[_keySize];
				_keySchedule[row][0] = _cipherKey[row][0];
				_keySchedule[row][1] = _cipherKey[row][1];
				_keySchedule[row][2] = _cipherKey[row][2];
				_keySchedule[row][3] = _cipherKey[row][3];
			}

			byte[] temp = new byte[4];

			for (var row = _keySize; row < _blockSize * (_numRounds + 1); ++row)
			{
				_keySchedule[row] = new byte[4];

				temp[0] = _keySchedule[row - 1][0];
				temp[1] = _keySchedule[row - 1][1];
				temp[2] = _keySchedule[row - 1][2];
				temp[3] = _keySchedule[row - 1][3];

				if (row % _keySize == 0)
				{
					temp = SubBytes(RotWord(temp));

					temp[0] = (byte)((int)temp[0] ^ (int)_rcon[row / _keySize][0]);
					temp[1] = (byte)((int)temp[1] ^ (int)_rcon[row / _keySize][1]);
					temp[2] = (byte)((int)temp[2] ^ (int)_rcon[row / _keySize][2]);
					temp[3] = (byte)((int)temp[3] ^ (int)_rcon[row / _keySize][3]);
				}
				else if (_keySize > 6 && (row % _keySize == 4))
				{
					temp = SubBytes(temp);
				}

				// w[row] = w[row-_keySize] xor temp
				_keySchedule[row][0] = (byte)((int)_keySchedule[row - _keySize][0] ^ (int)temp[0]);
				_keySchedule[row][1] = (byte)((int)_keySchedule[row - _keySize][1] ^ (int)temp[1]);
				_keySchedule[row][2] = (byte)((int)_keySchedule[row - _keySize][2] ^ (int)temp[2]);
				_keySchedule[row][3] = (byte)((int)_keySchedule[row - _keySize][3] ^ (int)temp[3]);

			}
		}
		#endregion
		#region Helper Methods
		byte[] Convert2DArrayTo1D(byte[][] twoDimensionalArray)
		{
			if (twoDimensionalArray[0] == null)
			{
				throw new ArgumentException("Must have a non empty array to convert");
			}
			var oneDimensionalArray = new List<byte>();

			for (var i = 0; i < twoDimensionalArray.Length; i++)
			{
				for (var j = 0; j < twoDimensionalArray[0].Length; j++)
				{
					oneDimensionalArray.Add(twoDimensionalArray[i][j]);
				}
			}

			return oneDimensionalArray.ToArray();
		}
		byte[][] Convert1DArrayTo2D(byte[] oneDimensionalArray, int rows, int columns)
		{
			if (rows * columns > oneDimensionalArray.Length)
			{
				throw new ArgumentException("Rows * Columns cannot be more than the 1D array length");
			}
			var matrix = new byte[rows][];
			for (var i = 0; i < rows; i++)
			{
				matrix[i] = new byte[columns];
				for (var j = 0; j < columns; j++)
				{
					matrix[i][j] = oneDimensionalArray[i * columns + j];
				}
			}
			return matrix;
		}
		byte ConvertToByte(BitArray bits)
		{
			if (bits.Count != 8)
			{
				throw new ArgumentException("bits");
			}

			byte[] bytes = new byte[2];
			bits.CopyTo(bytes, 0);
			return bytes[0];
		}
		byte ffmultiply(byte l, byte[] r)
		{
			for (int ffPos = 0; ffPos < 4; ffPos++)
				l ^= ffmultiply(l, r[ffPos]);

			return l;
		}
		byte ffmultiply(byte l, byte r)
		{
			var right = new BitArray(new byte[1] { r });
			var left = new BitArray(new byte[1] { l });
			var leftTmp = new BitArray(new byte[1] { l });

			var valuesToXor = new List<BitArray>();
			for (int numBits = 0; numBits < 8; numBits++)
			{
				if (right.Get(numBits))
				{
					for (int round = 0; round < numBits; round++)
					{
						leftTmp = XTime(leftTmp);
					}
					valuesToXor.Add(new BitArray(leftTmp));
					leftTmp = new BitArray(new byte[1] { l });
				}
			}

			var retVal = new byte[1];

			if (valuesToXor.Count == 0)
				return 0x00;
			else
			{
				var computedValue = new BitArray(valuesToXor[0]);
				for (int i = 1; i < valuesToXor.Count; i++)
				{
					computedValue = computedValue.Xor(valuesToXor[i]);
				}
				computedValue.CopyTo(retVal, 0);
			}
			return retVal[0];
		}
		byte[][] InitializeState(byte[] plainText)
		{
			if (plainText.Length != 4 * _blockSize)
				throw new ArgumentException("Plain Text must be 16 bytes long");

			return Convert1DArrayTo2D(plainText, 4, _blockSize);
		}
		byte[,] InitializeSbox()
		{
			return new byte[16, 16] {  // populate the Sbox matrix
/*        0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
/*0*/  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
/*1*/  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
/*2*/  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
/*3*/  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
/*4*/  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
/*5*/  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
/*6*/  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
/*7*/  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
/*8*/  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
/*9*/  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
/*a*/  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
/*b*/  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
/*c*/  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
/*d*/  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
/*e*/  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
/*f*/  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

		}
		byte[,] InitializeInvSbox()
		{
			return new byte[16, 16] { 
								{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
								{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
								{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
								{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
								{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
								{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
								{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
								{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
								{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
								{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
								{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
								{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
								{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
								{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
								{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
								{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};
		}
		byte[][] InitializeRCon()
		{

			return new byte[11][] {new byte[] {0x00, 0x00, 0x00, 0x00},
							  new byte[] {0x01, 0x00, 0x00, 0x00},
							  new byte[] {0x02, 0x00, 0x00, 0x00},
							  new byte[] {0x04, 0x00, 0x00, 0x00},
							  new byte[] {0x08, 0x00, 0x00, 0x00},
							  new byte[] {0x10, 0x00, 0x00, 0x00},
							  new byte[] {0x20, 0x00, 0x00, 0x00},
							  new byte[] {0x40, 0x00, 0x00, 0x00},
							  new byte[] {0x80, 0x00, 0x00, 0x00},
							  new byte[] {0x1b, 0x00, 0x00, 0x00},
							  new byte[] {0x36, 0x00, 0x00, 0x00} };
		}
		bool NeedsReducing(BitArray bits)
		{
			for (int i = 8; i < bits.Length; i++)
			{
				if (bits.Get(i)) return true;
			}

			return false;
		}
		byte[] RotWord(byte[] column)
		{
			if (column == null || column.Length != 4)
			{
				throw new ArgumentException("column is null or not length of 4");
			}

			// Shift each element 1 to the left
			var firstElement = column[0];
			for (var i = 0; i < column.Length - 1; i++)
			{
				column[i] = column[i + 1];
			}
			column[column.Length - 1] = firstElement;
			return column;
		}
		void SetNbNkNr(KeySize keySize)
		{
			this._blockSize = 4;

			if (keySize == KeySize.Bits128)
			{
				this._keySize = 4;
				this._numRounds = 10;
			}
			else if (keySize == KeySize.Bits192)
			{
				this._keySize = 6;
				this._numRounds = 12;
			}
			else if (keySize == KeySize.Bits256)
			{
				this._keySize = 8;
				this._numRounds = 14;
			}
		}
		byte[][] ShiftRowToTheLeft(byte[][] matrix, int shift)
		{
			var numRows = matrix.Length;
			var tmp = new List<byte>(numRows);
			for (var i = 0; i < numRows; i++)
			{
				tmp.Add(matrix[i][shift]);
			}
			var tmpRow = tmp.ToArray();

			for (var i = 0; i < numRows; i++)
			{
				var offset = (i + shift) % numRows;
				matrix[i][shift] = tmpRow[offset];
			}

			return matrix;
		}
		byte[][] ShiftRowToTheRight(byte[][] matrix, int shift)
		{
			var numRows = matrix.Length;
			var tmp = new List<byte>(numRows);
			for (var i = 0; i < numRows; i++)
			{
				tmp.Add(matrix[i][shift]);
			}
			var tmpRow = tmp.ToArray();

			for (var i = 0; i < numRows; i++)
			{
				var offset = i - shift;
				if (offset < 0) offset += numRows;
				matrix[i][shift] = tmpRow[offset];
			}

			return matrix;
		}
		BitArray XTime(BitArray bits)
		{
			var needsReducing = bits.Get(7);

			// Shift left
			for (var i = bits.Length - 1; i > 0; i--)
				bits.Set(i, bits.Get(i - 1));
			bits.Set(0, false);

			// Conditional XOR with 11b
			if (needsReducing)
				bits = bits.Xor(_1B);

			return bits;
		}
		BitArray XTime(BitArray bits, int bitLocation)
		{
			if (bitLocation <= 1)
				return bits;

			var needsReducing = bits.Get(7);

			// Shift left
			for (var i = bits.Length - 1; i > 0; i--)
				bits.Set(i, bits.Get(i - 1));
			bits.Set(0, false);

			// Conditional XOR with 11b
			if (needsReducing)
				bits = bits.Xor(_1B);

			return bits = XTime(bits, bitLocation - 1);
		}
		#endregion
		#endregion
	}
}
