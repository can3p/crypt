// (function(Crypt) {
/*  based on AES implementation in JavaScript (c) Chris Veness 2005-2010           */
/*   - see http://csrc.nist.gov/publications/PubsFIPS.html#197         */
(function(Crypt) {

	function xor(str1, str2) {
		var arr1 = str1.toByteArray(),
			arr2 = str2.toByteArray(),
			res = [];

		for(var i = 0; i < arr1.length; ++i) {
			res[i] = arr1[i] ^ arr2[i];
		}

		return String.fromByteArray(res);
	}

	function calcFullRound(s, Nb) {
		s[0][0] = Sbox[ s[0][0] ];
		s[0][1] = Sbox[ s[0][1] ];
		s[0][2] = Sbox[ s[0][2] ];
		s[0][3] = Sbox[ s[0][3] ];
		var tmp;
		var t = new Array(4);
		for (var r=1; r<Nb; ++r) {
			t[0] = Sbox[ s[r][( r + 0 ) % Nb] ];
			t[1] = Sbox[ s[r][( r + 1 ) % Nb] ];
			t[2] = Sbox[ s[r][( r + 2 ) % Nb] ];
			t[3] = Sbox[ s[r][( r + 3 ) % Nb] ];
			s[r][0] = t[0];
			s[r][1] = t[1];
			s[r][2] = t[2];
			s[r][3] = t[3];
		}

		var a = new Array(4);  // 'a' is a copy of the current column from 's'
		var b = new Array(4);  // 'b' is a•{02} in GF(2^8)
		for (var c=0; c<4; c++) {
			for (var i=0; i<4; i++) {
				a[i] = s[i][c];
				b[i] = s[i][c]&0x80 ? s[i][c]<<1 ^ 0x011b : s[i][c]<<1;
			}
			// a[n] ^ b[n] is a•{03} in GF(2^8)
			s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // 2*a0 + 3*a1 + a2 + a3
			s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 * 2*a1 + 3*a2 + a3
			s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + 2*a2 + 3*a3
			s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // 3*a0 + a1 + a2 + 2*a3
		}
		return s;
	}

	function calcRound(s, Nb) {
		s[0][0] = Sbox[ s[0][0] ];
		s[0][1] = Sbox[ s[0][1] ];
		s[0][2] = Sbox[ s[0][2] ];
		s[0][3] = Sbox[ s[0][3] ];
		var tmp;
		var t = new Array(4);
		for (var r=1; r<Nb; ++r) {
			t[0] = Sbox[ s[r][( r + 0 ) % Nb] ];
			t[1] = Sbox[ s[r][( r + 1 ) % Nb] ];
			t[2] = Sbox[ s[r][( r + 2 ) % Nb] ];
			t[3] = Sbox[ s[r][( r + 3 ) % Nb] ];
			s[r][0] = t[0];
			s[r][1] = t[1];
			s[r][2] = t[2];
			s[r][3] = t[3];
		}

		return s;
	}

	function subBytes(s, Nb) { // apply SBox to state S [§5.1.1]
		for (var r=0; r<4; r++) {
			for (var c=0; c<Nb; c++) s[r][c] = Sbox[s[r][c]];
		}
		return s;
	}

	function shiftRows(s, Nb) { // shift row r of state S left by r bytes [§5.1.2]
		var t = new Array(4);
		for (var r=1; r<4; r++) {
			for (var c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];  // shift into temp copy
			for (var c=0; c<4; c++) s[r][c] = t[c]; // and copy back
		}  // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
		return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
	}

	function mixCloumns(s, Nb) {   // combine bytes of each col of state S [§5.1.3]
		var a = new Array(4);  // 'a' is a copy of the current column from 's'
		var b = new Array(4);  // 'b' is a•{02} in GF(2^8)
		for (var c=0; c<4; c++) {
			for (var i=0; i<4; i++) {
				a[i] = s[i][c];
				b[i] = s[i][c]&0x80 ? s[i][c]<<1 ^ 0x011b : s[i][c]<<1;
			}
			// a[n] ^ b[n] is a•{03} in GF(2^8)
			s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // 2*a0 + 3*a1 + a2 + a3
			s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 * 2*a1 + 3*a2 + a3
			s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + 2*a2 + 3*a3
			s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // 3*a0 + a1 + a2 + 2*a3
		}
		return s;
	}

	function addRoundKey(state, w, rnd, Nb) {  // xor Round Key into state S [§5.1.4]
		for (var r=0; r<4; r++) {
			for (var c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
		}
		return state;
	}

	function subBytesInv(s, Nb) {
		for (var r=0; r<4; r++) {
			for (var c=0; c<Nb; c++) s[r][c] = SboxInv[s[r][c]];
		}
		return s;
	}

	function shiftRowsInv(s, Nb) { // shift row r of state S left by r bytes [§5.1.2]
		var t = new Array(4);
		for (var r=1; r<4; r++) {
			for (var c=0; c<4; c++) t[c] = s[r][(Nb+c-r)%Nb];  // shift into temp copy
			for (var c=0; c<4; c++) s[r][c] = t[c]; // and copy back
		} // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
		return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
	}

	function mixCloumnsInv(s, Nb) {
		var a = new Array(4);
		for (var c=0; c<4; c++) {
			for (var i=0; i<4; ++i) {
				a[i] = s[i][c];
			}

			s[0][c] = gmul(a[0],14) ^ gmul(a[3],9) ^ gmul(a[2],13) ^ gmul(a[1],11);
			s[1][c] = gmul(a[1],14) ^ gmul(a[0],9) ^ gmul(a[3],13) ^ gmul(a[2],11);
			s[2][c] = gmul(a[2],14) ^ gmul(a[1],9) ^ gmul(a[0],13) ^ gmul(a[3],11);
			s[3][c] = gmul(a[3],14) ^ gmul(a[2],9) ^ gmul(a[1],13) ^ gmul(a[0],11);
		}
		return s;
	}

	function subWord(w) { // apply SBox to 4-byte word w
		for (var i=0; i<4; i++) w[i] = Sbox[w[i]];
		return w;
	}

	function rotWord(w) { // rotate 4-byte word w left by one byte
		var tmp = w[0];
		for (var i=0; i<3; i++) w[i] = w[i+1];
		w[3] = tmp;
		return w;
	}

	function gmul(a,b) { //multiplication in Galois Field
		var s, q;
		var z = 0;

		s = LogTable[a] + LogTable[b];
		s%= 255;

		s = AntiLogTable[s];
		q = s;

		if( a == 0) {
			s = z;
		}
		else {
			s = q;
		}
		if(b == 0) {
			s = z;
		}
		else {
			q = z;
		}

		return s;
	}

	// Sbox is pre-computed multiplicative inverse in GF(2^8) used in SubBytes and KeyExpansion [§5.1.1]
	var Sbox =  [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
				 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
				 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
				 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
				 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
				 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
				 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
				 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
				 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
				 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
				 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
				 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
				 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
				 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
				 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
				 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

	var SboxInv = [  82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
					124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
					 84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
					  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
					114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
					108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
					144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
					208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
					 58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
					150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
					 71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
					252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
					 31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
					 96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
					160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
					 23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125];

	/* Log table using 0xe5 (229) as the generator */
	var LogTable = [  0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36,
					0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
					0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f,
					0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
					0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53,
					0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
					0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21,
					0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
					0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4,
					0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
					0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13,
					0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
					0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12,
					0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
					0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56,
					0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
					0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3,
					0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
					0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf,
					0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
					0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67,
					0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
					0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34,
					0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
					0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7,
					0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
					0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a,
					0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
					0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c,
					0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
					0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0,
					0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38 ];

	/* Anti-log table: */
	var AntiLogTable = [ 0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12,
						0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
						0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a,
						0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
						0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29,
						0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
						0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d,
						0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
						0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f,
						0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
						0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85,
						0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
						0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7,
						0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
						0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d,
						0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
						0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39,
						0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
						0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd,
						0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
						0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84,
						0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
						0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2,
						0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
						0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c,
						0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
						0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c,
						0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
						0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7,
						0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
						0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6,
						0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01 ];


	// Rcon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
	var Rcon = [ [0x00, 0x00, 0x00, 0x00],
				 [0x01, 0x00, 0x00, 0x00],
				 [0x02, 0x00, 0x00, 0x00],
				 [0x04, 0x00, 0x00, 0x00],
				 [0x08, 0x00, 0x00, 0x00],
				 [0x10, 0x00, 0x00, 0x00],
				 [0x20, 0x00, 0x00, 0x00],
				 [0x40, 0x00, 0x00, 0x00],
				 [0x80, 0x00, 0x00, 0x00],
				 [0x1b, 0x00, 0x00, 0x00],
				 [0x36, 0x00, 0x00, 0x00] ];

	Crypt.AES = {
		/**
		 * AES Cipher function: encrypt 'input' state with Rijndael algorithm
		 *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage
		 *
		 * @param {Number[]} input 16-byte (128-bit) input state array
		 * @param {Number[][]} w   Key schedule as 2D byte-array (Nr+1 x Nb bytes)
		 * @returns {Number[]} Encrypted output state array
		 */
		cipher: function(input, w) { // main Cipher function [§5.1]
			var Nb = 4;   // block size (in words): no of columns in state (fixed at 4 for AES)
			var Nr = w.length/Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys

			var state = [[],[],[],[]];  // initialise 4xNb byte-array 'state' with input [§3.4]
			for (var i=0; i<4*Nb; i++) state[i%4][Math.floor(i/4)] = input[i];

			state = addRoundKey(state, w, 0, Nb);

			for (var round=1; round<Nr; round++) {
				//state = subBytes(state, Nb);
				//state = shiftRows(state, Nb);
				state = calcFullRound(state, Nb);
				//state = mixCloumns(state, Nb);
				state = addRoundKey(state, w, round, Nb);
			}

			state = calcRound(state, Nb);
			state = addRoundKey(state, w, Nr, Nb);

			var output = new Array(4*Nb);  // convert state to 1-d array before returning [§3.4]
			for (var i=0; i<4*Nb; i++) output[i] = state[i%4][Math.floor(i/4)];
			return output;
		},

		/**
		 * AES Deipher function: decrypt 'input' state with Rijndael algorithm
		 *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage
		 *
		 * @param {Number[]} input 16-byte (128-bit) input state array
		 * @param {Number[][]} w   Key schedule as 2D byte-array (Nr+1 x Nb bytes)
		 * @returns {Number[]} Encrypted output state array
		 */
		decipher: function(input, w) {
			var Nb = 4;
			var Nr = w.length/Nb - 1;

			var state = [[],[],[],[]];
			for (var i=0; i<4*Nb; i++) state[i%4][Math.floor(i/4)] = input[i];

			state = addRoundKey(state, w, Nr, Nb);
			state = shiftRowsInv(state, Nb);
			state = subBytesInv(state, Nb);

			for (var round=Nr-1; round >= 1; round--) {
				state = addRoundKey(state, w, round, Nb);
				state = mixCloumnsInv(state, Nb);
				state = shiftRowsInv(state, Nb);
				state = subBytesInv(state, Nb);
			}

			state = addRoundKey(state, w, 0, Nb);

			var output = new Array(4*Nb);  // convert state to 1-d array before returning [§3.4]
			for (var i=0; i<4*Nb; i++) output[i] = state[i%4][Math.floor(i/4)];
			return output;
		},

		cipherCBC: function(input, key, iv) {
			var Nb = 16, //block size in bytes
				expanded = Crypt.AES.keyExpansion(key.toByteArray());

			var charDiv = Nb - ((input.length) % Nb);
            console.log(charDiv);
			//input += String.fromCharCode(10);
			for(var c = 0; c < charDiv; ++c) {
				input += String.fromCharCode(charDiv);
			}

            console.log(input.toHexString());

			var blockCount = Math.ceil(input.length/Nb);
			var ciphertxt = "";
			var textBlock = "";
			var state = iv;

			for (var b=0; b<blockCount; b++) {
				textBlock = input.substr(b*Nb, Nb);
				state = xor(state, textBlock);

				state = String.fromByteArray( Crypt.AES.cipher( state.toByteArray(), expanded ) );
				ciphertxt += state;
			}
			return ciphertxt;
		},

		decipherCBC: function(input, key, iv) {
			var Nb = 16, //block size in bytes
				expanded = Crypt.AES.keyExpansion(key.toByteArray());

			var blockCount = Math.ceil(input.length/Nb),
				state = iv,
				plain = "",
				textBlock = "",
				decState = "";

			for( var b=0; b < blockCount; ++b ) {
				textBlock = input.substr(b*Nb, Nb);
				decState = String.fromByteArray( Crypt.AES.decipher( textBlock.toByteArray(), expanded ) );

				plain += xor( state, decState );
				state = textBlock;
			}

			var endByte = plain.charCodeAt( plain.length-1 );

			plain = plain.substr( 0, plain.length - endByte );
			return plain;
		},


		/**
		 * Perform Key Expansion to generate a Key Schedule
		 *
		 * @param {Number[]} key Key as 16/24/32-byte array
		 * @returns {Number[][]} Expanded key schedule as 2D byte-array (Nr+1 x Nb bytes)
		 */
		keyExpansion: function(key) {  // generate Key Schedule (byte-array Nr+1 x Nb) from Key [§5.2]
			var Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
			var Nk = key.length/4  // key length (in words): 4/6/8 for 128/192/256-bit keys
			var Nr = Nk + 6;   // no of rounds: 10/12/14 for 128/192/256-bit keys

			var w = new Array(Nb*(Nr+1));
			var temp = new Array(4);

			for (var i=0; i<Nk; i++) {
				var r = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
				w[i] = r;
			}

			for (var i=Nk; i<(Nb*(Nr+1)); i++) {
				w[i] = new Array(4);
				for (var t=0; t<4; t++) temp[t] = w[i-1][t];
				if (i % Nk == 0) {
					temp = subWord(rotWord(temp));
					for (var t=0; t<4; t++) temp[t] ^= Rcon[i/Nk][t];
				} else if (Nk > 6 && i%Nk == 4) {
					temp = subWord(temp);
				}
				for (var t=0; t<4; t++) w[i][t] = w[i-Nk][t] ^ temp[t];
			}

		  return w;
		}
	};
})(window.Crypt = window.Crypt || {});
