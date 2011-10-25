#!/usr/bin/env python

from Crypto.Cipher import AES

def ByteToHex( byteStr ):
	return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def HexToByte( hexStr ):
	bytes = []

	hexStr = ''.join( hexStr.split(" ") )

	for i in range(0, len(hexStr), 2):
		bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

	return ''.join( bytes )

IV = HexToByte('18 47 01 D1 94 A0 9E 2C 71 C2 34 FC 1F 15 00 E3')
KEY = HexToByte('7C BC 90 2C 1A 5C 6C 31 86 FC 0A 12 DD 5F 2A 9E 40 E4 F2 EE B4 98 E0 CE 59 22 13 6E 34 2D 41 B1')
PlainStr = 'some text to cipher 1245 '
print PlainStr
PlainStr = PlainStr + ( ( 16 - len(PlainStr) % 16 ) % 16 ) * chr(len(PlainStr))
print PlainStr
print ByteToHex(PlainStr)

cipher = AES.new(KEY, AES.MODE_CBC, IV)
encrypted = cipher.encrypt(PlainStr)
print 'encrypted'
print ByteToHex(encrypted)
cipher = AES.new(KEY, AES.MODE_CBC, IV)
decrypted = cipher.decrypt(encrypted)
print decrypted
print ByteToHex(decrypted)

print decrypted[:ord(decrypted[-1])]

# print ByteToHex(IV)
# print ByteToHex(KEY)
