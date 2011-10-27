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

import hashlib
hash = hashlib.sha256()
hash.update("1234")
# print ByteToHex(hash.digest())
# exit(0)

IV = HexToByte('3b b4 6f a4 d7 6f 16 cd 7a 6d ee e6 6d 0a a0 8d')
KEY = hash.digest()
PlainStr = 'aaCrypted text This is that crypted long test please look at me bla bla bla'
print ( ( 16 - (len(PlainStr)) % 16 ) ) + len(PlainStr)
PlainStr = PlainStr + ( ( 16 - len(PlainStr) % 16 ) ) * chr(len(PlainStr))
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
