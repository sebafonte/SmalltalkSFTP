

!String publicMethods !

findDelimiters: delimiters startingAt: start 
	"Answer the index of the character within the receiver, starting at start, that matches one of the delimiters. If the receiver does not contain any of the delimiters, answer size + 1."

	start to: self size do: [:i |
		delimiters do: [:delim | delim = (self at: i) ifTrue: [^ i]]].
	^ self size + 1!

findTokens: delimiters
	"Answer the collection of tokens that result from parsing self.  Return strings between the delimiters.  Any character in the Collection delimiters marks a border.  Several delimiters in a row are considered as just one separation.  Also, allow delimiters to be a single character."

	| tokens keyStart keyStop separators |

	tokens := OrderedCollection new.
	separators := delimiters class == Character 
		ifTrue: [ Array with: delimiters ]
		ifFalse: [ delimiters ].
	keyStop := 1.
	[keyStop <= self size] whileTrue:
		[keyStart := self skipDelimiters: separators startingAt: keyStop.
		keyStop := self findDelimiters: separators startingAt: keyStart.
		keyStart < keyStop
			ifTrue: [tokens add: (self copyFrom: keyStart to: (keyStop - 1))]].
	^tokens!

skipDelimiters: delimiters startingAt: start 
	"Answer the index character within the receiver, starting at start, that does NOT match one of the delimiters. If the receiver does not contain any of the delimiters, answer size + 1.  Assumes the delimiters to be a non-empty string."

	start to: self size do: [:i |
		delimiters detect: [:delim | delim = (self at: i)]
				ifNone: [^ i]].
	^ self size + 1!

sshLong
	"Answer a 32bit value converted from network order to host order."

	^self sshLongAt: 1!

sshLongAt: anInteger
	"Answer a 32bit value converted from network order to host order."

	| index |
	index := anInteger - 1 * 4.
	^((self uint8At: index) bitShift: 24) + ((self uint8At: index + 1) bitShift: 16) +
		((self uint8At: index + 2) bitShift: 8) + (self uint8At: index + 3)!

sshLongAt: longIndex from: startIndex
	"Answer a 32bit value converted from network order to host order."

	| index |
	index := longIndex - 1 * 4 + startIndex - 1.
	^((self uint8At: index) bitShift: 24) + ((self uint8At: index + 1) bitShift: 16) +
		((self uint8At: index + 2) bitShift: 8) + (self uint8At: index + 3)! !


Object subclass: #CompressionAlgorithm
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!CompressionAlgorithm class publicMethods !

description

	^self subclassResponsibility!

fromDescription: aString

	^(self allSubclasses
			detect: [:each | each description = aString])
				new
		!

isAbstract

	^self == ##(self)! !

!CompressionAlgorithm publicMethods !

compress: aString
	"Answer a string with compressed data of <aString>."

	^self subclassResponsibility! !

CompressionAlgorithm initializeAfterLoad!


CompressionAlgorithm subclass: #NullCompression
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!NullCompression class publicMethods !

description

	^'none'! !

!NullCompression publicMethods !

compress: aString
	"Answer a string with compressed data of <aString>."

	^aString! !

NullCompression initializeAfterLoad!


Object subclass: #DiffieHellman
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!DiffieHellman class publicMethods !

fromDescription: aString

	^(self allSubclasses
			detect: [:each | each description = aString])
				new
		!

isAbstract

	^self == ##(self)! !

!DiffieHellman publicMethods !

byteFromBinary: aString

	| value |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		each = $1 ifTrue: [value := value + (2 raisedTo: index - 1)]].
	^value asCharacter!

correctKey: aKey
	"Answer a string which represents <aKey> without redundant zeros, adding positive byte flag if neccesary."

	| correctKey |
	"Eliminate redundand 0's."
	correctKey := aKey.
	[correctKey first value = 0] whileTrue: [
		correctKey := correctKey copyFrom: 2 to: correctKey size].
	"Add 0 for positive."
	^(correctKey first value bitAnd: 128) = 0 
		ifTrue: [correctKey]
		ifFalse: [0 asCharacter asString, correctKey]
	!

createNewKeyFor: serverKey randomValue: aNumber
	"Answer a new generated key using <serverKey> and <aNumber>."

	| bytesValue key |
	bytesValue := self integerFromString: serverKey.
	key := self raise: bytesValue toInteger: aNumber modulo: self initialPrime.
	^self correctKey: (self integerToString: key bits: 1024)!

generateKey: keyLength x: x

	| p q g e |
	p := self initialPrime.
	q := 1.
	q := q bitShift: 2 * keyLength.
	q := q - 1.
	g := 2.
	e := self raise: g toInteger: x modulo: p.
	^self correctKey: (self integerToString: e bits: 1032)
	!

initialPrime
	"Answer the initial prime for diffie-hellman key."

	^self initialPrimeHexValue abrAsInteger: 16!

initialPrimeHexValue
	"Answer a string with the representation of the initial prime of the receiver."

	^self subclassResponsibility!

integerFromString: aString
	"Answer the integer represented in <aString> using little endian representation."

	| value char baseIndex |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		char := each value.
		baseIndex := index - 1 * 8.
		value := value 	+ ((char bitAt: 1) * (2 raisedTo: baseIndex))
										+ ((char bitAt: 2) * (2 raisedTo: baseIndex + 1))
										+ ((char bitAt: 3) * (2 raisedTo: baseIndex + 2))
										+ ((char bitAt: 4) * (2 raisedTo: baseIndex + 3))
										+ ((char bitAt: 5) * (2 raisedTo: baseIndex + 4))
										+ ((char bitAt: 6) * (2 raisedTo: baseIndex + 5))
										+ ((char bitAt: 7) * (2 raisedTo: baseIndex + 6))
										+ ((char bitAt: 8) * (2 raisedTo: baseIndex + 7)) ].
	^value!

integerToString: anInteger
	"Answer a string representing <anInteger> in little endian format, padded to 32 bits."

	^self integerToString: anInteger bits: 32!

integerToString: anInteger bits: aNumber
	"Answer a string representing <anInteger> in little endian format, padded to <aNumber> bits."

	| stream index binary |
	binary := ''.
	stream := ReadWriteStream on: ''.
	index := 0.

	(anInteger printStringRadix: 2 padTo: aNumber) reverse do: [:each | 
		index := index + 1.
		binary := binary, each asString.
		index = 8 ifTrue: [
			index := 0. 
			stream nextPut: (self byteFromBinary: binary reverse).
			binary := '' ]].

	index > 0 ifTrue: [
		1 to: 8 - index do: [:each | binary := $0 asString, binary].
		stream nextPut: (self byteFromBinary: binary)].
	
	^stream contents reverse
	!

raise: aNumber toInteger: t1 modulo: t2 
	"Modular exponentiation of <aNumber> to <t1> modulous <t2>."

	t1 = 0 ifTrue: [^1].
	t1 even	ifTrue: [^(self raise: aNumber toInteger: t1 // 2 modulo: t2) squared \\ t2].
	^aNumber * (self raise: aNumber toInteger: t1 - 1 modulo: t2) \\ t2! !

DiffieHellman initializeAfterLoad!


DiffieHellman subclass: #DiffieHellmanGroup1
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!DiffieHellmanGroup1 class publicMethods !

description

	^'diffie-hellman-group1-sha1'! !

!DiffieHellmanGroup1 publicMethods !

initialPrimeHexValue
	"Answer a string with the representation of the initial prime of the receiver."

	^'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74', 
	 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437', 
	 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED', 
	 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF'! !

DiffieHellmanGroup1 initializeAfterLoad!


DiffieHellman subclass: #DiffieHellmanGroup14
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!DiffieHellmanGroup14 class publicMethods !

description

	^'diffie-hellman-group14-sha1'!

isAbstract

	^self == ##(self)! !

!DiffieHellmanGroup14 publicMethods !

initialPrimeHexValue
	"Answer a string with the representation of the initial prime of the receiver."

	^'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74',
   '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437',
	 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED',
	 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05',
	 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB',
	 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B',
	 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718',
	 '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'! !

DiffieHellmanGroup14 initializeAfterLoad!


Object subclass: #EncryptionAlgorithm
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!EncryptionAlgorithm class publicMethods !

description

	^self subclassResponsibility!

fromDescription: aString

	^(self allSubclasses
			detect: [:each | each description = aString])
				new
		!

isAbstract

	^self == ##(self)! !

!EncryptionAlgorithm publicMethods !

decrypt: aString

	^self subclassResponsibility!

encrypt: aString

	^self subclassResponsibility! !

EncryptionAlgorithm initializeAfterLoad!


EncryptionAlgorithm subclass: #NullEncryption
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!NullEncryption class publicMethods !

description

	^'none'! !

!NullEncryption publicMethods !

decrypt: aString

	^aString!

encrypt: aString

	^aString! !

NullEncryption initializeAfterLoad!


EncryptionAlgorithm subclass: #RC4Encryption
    instanceVariableNames: 'key encryptStream decryptStream encryptIndex decryptIndex '
    classVariableNames: ''
    poolDictionaries: ''!

!RC4Encryption class publicMethods !

defaultKey

	^(1 to: self defaultKeyLength) 
		inject: '' 
		into: [:total :each | total, $a asString]!

defaultKeyLength

	^32!

description

	^'arcfour256'!

new

	^super new
		initialize! !

!RC4Encryption publicMethods !

decrypt: aString

	| i j keyStream newText aux |
	keyStream := decryptStream.
	i := decryptIndex at: 1.
	j := decryptIndex at: 2.
	newText := String new: aString size.

	aString doWithIndex: [:each :index |
		i := i + 1 bitAnd: 255.
		j := (j + (keyStream at: i + 1)) bitAnd: 255. 
		aux := keyStream at: i + 1.
		keyStream at: i + 1 put: (keyStream at: j + 1).
		keyStream at: j + 1 put: aux.
		aux := keyStream at: (((keyStream at: i + 1) + (keyStream at: j + 1)) bitAnd: 255) + 1.
		newText at: index put: (each value bitXor: aux) asCharacter].

	decryptStream := keyStream.
	decryptIndex at: 1 put: i.
	decryptIndex at: 2 put: j.
	^newText
	
	!

defaultKeyLength

	^self class defaultKeyLength!

encrypt: aString

	| i j keyStream newText aux |
	keyStream := encryptStream.
	i := encryptIndex at: 1.
	j := encryptIndex at: 2.
	newText := String new: aString size.

	aString doWithIndex: [:each :index |
		i := i + 1 bitAnd: 255.
		j := (j + (keyStream at: i + 1)) bitAnd: 255. 
		aux := keyStream at: i + 1.
		keyStream at: i + 1 put: (keyStream at: j + 1).
		keyStream at: j + 1 put: aux.
		aux := keyStream at: (((keyStream at: i + 1) + (keyStream at: j + 1)) bitAnd: 255) + 1.
		newText at: index put: (each value bitXor: aux) asCharacter].

	encryptStream := keyStream.
	encryptIndex at: 1 put: i.
	encryptIndex at: 2 put: j.
	^newText
	
	!

initialize
	"Initialize the receiver."

	self key: self class defaultKey!

key

	^key!

key: aByteArray

	| keySize keyStream aux j a b|
	key := aByteArray.
	keySize := key size.
	keyStream := Array new: 256.

	0 to: 255 do: [:i | keyStream at: i + 1 put: i].
	j := 0.
	0 to: 255 do: [:i | 
		a := (keyStream at: i + 1).
		b := (aByteArray at: (i rem: keySize) + 1) value.

		j := j + a + b bitAnd: 255.
		aux := keyStream at: i + 1.
		keyStream at: i + 1 put: (keyStream at: j + 1).
		keyStream at: j + 1 put: aux].

	encryptIndex := Array with: 0 with: 0.
	decryptIndex := Array with: 0 with: 0.
	encryptStream := keyStream.
	decryptStream := keyStream!

keyLength

	^self key size! !

RC4Encryption initializeAfterLoad!


Object subclass: #HMACAlgorithm
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!HMACAlgorithm class publicMethods !

description

	^self subclassResponsibility!

fromDescription: aString

	^(self allSubclasses
			detect: [:each | each description = aString])
				new
		!

isAbstract

	^self == ##(self)! !

!HMACAlgorithm publicMethods !

keyLength
	"Answer key length for the receiver."

	^self subclassResponsibility! !

HMACAlgorithm initializeAfterLoad!


HMACAlgorithm subclass: #HMACSHA1
    instanceVariableNames: 'key ipad opad l b shaEngine '
    classVariableNames: ''
    poolDictionaries: ''!

!HMACSHA1 class publicMethods !

defaultKeyLength
	
	^20!

description

	^'hmac-sha1'!

new

	^super new
		initialize! !

!HMACSHA1 publicMethods !

basicHash: aString
	"Answer a string with <aString> hashed contents."	 

	^String withAll: 
		((shaEngine digest: aString asByteArray) 
			collect: [:each | each asCharacter])

!

bitwiseXor: aString with: anotherString
	"Answer the result of bitwise xor operation of <aString> with <anotherString>."

	| stream value |
	stream := ReadWriteStream on: ''.
	1 to: aString size do: [:each | 
		value := (aString at: each) value bitXor: (anotherString at: each) value.
		stream nextPut: value asCharacter].
	^stream contents

	!

hash: aString
	"Answer a string with <aString> hashed contents."	 

	| newKey temp output |
	newKey := key size > b ifTrue: [self basicHash: key] ifFalse: [key].
	newKey := self pad: key.	
	temp := self bitwiseXor: ipad with: newKey.
	temp := temp, aString.
	temp := self basicHash: temp.
	output := self bitwiseXor: opad with: newKey.
	output := output, temp.
	^(self basicHash: output) copyFrom: 1 to: l

!

initialize
	"Initialize the receiver."

	l := 20.
	b := 64.
	ipad := ''.
	opad := ''.
	1 to: b do: [:each | ipad := ipad, 54 asCharacter asString]. 
	1 to: b do: [:each | opad := opad, 92 asCharacter asString].
	shaEngine := ShaEngine new.
	key := ''.
	self class defaultKeyLength timesRepeat: [key := key, ' ']
	
	!

key
	
	^key!

key: aString
	
	key := aString!

keyLength
	"Answer key length for the receiver."

	^key size!

pad: aString
	"Answer <aString> padded for the receiver."

	^aString, (String withAll: ((1 to: b) collect: [:each | 0 asCharacter]))
		copyFrom: 1 to: b! !

HMACSHA1 initializeAfterLoad!







!Integer publicMethods !

sshBit32Shift: offset

	offset = 0 ifTrue: [^self].
	^offset < 0
		ifTrue: [(self bitAnd: 16rFFFFFFFF) bitShift: offset]
		ifFalse: [(self bitShift: offset) bitAnd: 16rFFFFFFFF]! !


Object subclass: #NetClient
    instanceVariableNames: 'connectInfo socket responseCode lastResponse pendingResponses '
    classVariableNames: ''
    poolDictionaries: ''!

!NetClient class publicMethods !

hostName: aString
		"Answer a new disconnected instance of the receiver."

	^self new
		hostName: aString;
		yourself!

loginSpec: aRemoteConnectionSpec
		"Answer a new connected instance of the receiver."

	^self new
		connectionInfo: aRemoteConnectionSpec;
		yourself! !

!NetClient publicMethods !

checkForPendingError
	"If data is waiting, check it to catch any error reports.
	In case the response is not an error, push it back."

	(self socket notNil and: [ self socket isDataAvailable ])
		ifFalse: [ ^self ].
	self fetchNextResponse.
	self
		checkResponse: self lastResponse
		onError: [ :response | Error signal: response ]
		onWarning: [:response | Warning signal: response ].
	"if we get here, it wasn't an error"
	self pushResponse: self lastResponse!

checkResponse
	"Get the response from the server and check for errors."

	self
		checkResponseOnError: [ :response | Error signal: response ]
		onWarning: [ :response | Warning signal: response ].!

checkResponse: aResponse onError: errorBlock onWarning: warningBlock
	"Get the response from the server and check for errors. Invoke one of the blocks if an error or warning is encountered. See class comment for classification of error codes."

	self responseIsError
		ifTrue: [ errorBlock value: aResponse ].
	self responseIsWarning
		ifTrue: [ warningBlock value: aResponse ].!

checkResponseOnError: errorBlock onWarning: warningBlock
	"Get the response from the server and check for errors. Invoke one of the blocks if an error or warning is encountered. See class comment for classification of error codes."

	self fetchPendingResponse.
	self checkResponse: self lastResponse onError: errorBlock onWarning: warningBlock!

close
	self socket isNil
		ifFalse: [
			self socket close.
			socket := nil ].
	responseCode := lastResponse := nil.
	!

connect
		"Connect socket and answer the receiver."

	self socket isNil
		ifTrue: [
			self socket: (AbtSocketStream createClientSocketToHost: self hostName port: self defaultPortNumber) ].
	^self!

connectionInfo
	connectInfo ifNil: [connectInfo := RemoteConnectionSpec new].
	^connectInfo!

connectionInfo: aRemoteConnectionSpec

	connectInfo := aRemoteConnectionSpec!

defaultPortNumber

	^self class defaultPortNumber!

determineResponseCode
	self lastResponse size >= 3
		ifFalse: [^0].
	^[(self lastResponse copyFrom: 1 to: 3) asNumber]
		on: Error
		do: [:ex | ex return: 0]!

ensureConnection
		"Create socket and connect."

	| procesoConexion rc timeout limitTime |

	timeout := 120000.
	limitTime := (DateAndTime now) + (Duration milliseconds: timeout).

	self isConnected ifTrue: [ ^self ].
	self socket notNil	ifTrue: [ self socket close ].

	procesoConexion := [
		self connect.
		self checkResponse.
		rc := self login ] fork.

	[ DateAndTime now <= limitTime ] whileTrue: [
			(Delay forSeconds: 1) wait.
			rc isNil ifFalse: [ ^rc ] ].

	rc isNil ifTrue: [
		Processor terminate: procesoConexion.
		rc := AbtError errorText: 'Error de timeout conectando al FTP' ].

	^rc!

fetchNextResponse
	"The telnet protocol allows multiple line replies."

	| response result |
	self socket isNil
		ifTrue: [ ^self ].

	result := WriteStream on: ''.
	[response := self socket nextLineCrOrLf.
	self responseIsContinuation: response]
		whileTrue: [result nextPutAll: response; cr].
	result nextPutAll: response.
	self lastResponse: result contents!

fetchPendingResponse
	^pendingResponses isNil
		ifTrue: [self fetchNextResponse; lastResponse]
		ifFalse: [self popResponse]!

hostName
	^self connectionInfo hostname!

hostName: aHostName
	^self connectionInfo hostname: aHostName!

isConnected
	^socket notNil
		and: [socket socket isClosed not]!

lastResponse
	^lastResponse!

lastResponse: aString

	lastResponse := aString.
	responseCode := self determineResponseCode!

lookForCode: code
	"We are expecting a certain code next."

	self
		lookForCode: code
		ifDifferent: [:response | (Error signal: response)]
!

lookForCode: code ifDifferent: handleBlock
	"We are expecting a certain code next."

	self fetchNextResponse.
	self responseCode == code
		ifFalse: [handleBlock value: self lastResponse]
!

password
	^self connectionInfo password!

password: aString
	^self connectionInfo password: aString!

pendingResponses
	pendingResponses isNil
		ifTrue: [pendingResponses := OrderedCollection new].
	^pendingResponses!

popResponse
	| pendingResponse |
	pendingResponse := self pendingResponses removeFirst.
	pendingResponses isEmpty
		ifTrue: [pendingResponses := nil].
	^pendingResponse!

pushResponse: aResponse
	self pendingResponses add: aResponse!

responseCode
	^responseCode!

responseIsContinuation
		"Verify whether last response buffer has multiple lines."

	^(self lastResponse size > 3
		and: [(self lastResponse at: 4) == $-])!

responseIsContinuation: response
		"Verify whether last response buffer has multiple lines."

	^((response size > 3
		and: [(response at: 4) == $-]) or: [
			response asNumber = 0 ])!

responseIsError
		"Answer whether current response is a warning."
	^self responseCode between: 500 and: 599!

responseIsWarning
		"Answer whether current response is a warning."
	^self responseCode between: 400 and: 499!

sendCommand: aString
		"Send command <aString>."

	self socket
		nextPutAll: aString;
		nextPutAll: (Character cr asString, Character lf asString).
	self socket flush!

socket
	^socket!

socket: aSocketStream
	socket := aSocketStream!

user
	^self connectionInfo userid!

user: aString
	^self connectionInfo userid: aString! !

NetClient initializeAfterLoad!


NetClient subclass: #FTPClient
    instanceVariableNames: 'dataSocket transferedData fileSize '
    classVariableNames: ''
    poolDictionaries: ''!

!FTPClient class publicMethods !

defaultPortNumber
	^21!

rawResponseCodes
	^#(200 'Command okay.'
	500 'Syntax error, command unrecognized. This may include errors such as command line too long.'
	501 'Syntax error in parameters or arguments.'
	202 'Command not implemented, superfluous at this site.'
	502 'Command not implemented.'
	503 'Bad sequence of commands.'
	504 'Command not implemented for that parameter.'
	110 'Restart marker reply. In this case, the text is exact and not left to the particular implementation; it must read: MARK yyyy = mmmm Where yyyy is User-process data stream marker, and mmmm server''s equivalent marker (note the spaces between markers and "=").'
	211 'System status, or system help reply.'
	212 'Directory status.'
	213 'File status.'
	214 'Help message. On how to use the server or the meaning of a particular non-standard command. This reply is useful only to the human user.'
	215 'NAME system type. Where NAME is an official system name from the list in the Assigned Numbers document.'
	120 'Service ready in nnn minutes.'

	220 'Service ready for new user.'
	221 'Service closing control connection. Logged out if appropriate.'
	421 'Service not available, closing control connection. This may be a reply to any command if the service knows it must shut down.'
	125 'Data connection already open; transfer starting.'
	225 'Data connection open; no transfer in progress.'
	425 'Can''t open data connection.'
	226 'Closing data connection. Requested file action successful (for example, file transfer or file abort).'
	426 'Connection closed; transfer aborted.'
	227 'Entering Passive Mode (h1,h2,h3,h4,p1,p2).'

	230 'User logged in, proceed.'
	530 'Not logged in.'
	331 'User name okay, need password.'
	332 'Need account for login.'
	532 'Need account for storing files.'
	150 'File status okay; about to open data connection.'
	250 'Requested file action okay, completed.'
	257 '"PATHNAME" created.'
	350 'Requested file action pending further information.'
	450 'Requested file action not taken. File unavailable (e.g., file busy).'
	550 'Requested action not taken. File unavailable (e.g., file not found, no access).'
	451 'Requested action aborted. Local error in processing.'
	551 'Requested action aborted. Page type unknown.'
	452 'Requested action not taken. Insufficient storage space in system.'
	552 'Requested file action aborted. Exceeded storage allocation (for current directory or dataset).'
	553 'Requested action not taken. File name not allowed.')! !

!FTPClient publicMethods !

abortDataConnection
	self sendCommand: 'ABOR'.
	self closeDataSocket!

appendFileNamed: filePath as: fileNameOnServer
	"FTP a file to the server."


	| file rc |
	(file := CfsReadFileStream open: filePath) isCfsError
		ifTrue: [ ^(Error signal: file message)  ].
	rc := (self appendFileStreamContents: file as: fileNameOnServer).
	file close.
	^rc!

appendFileStreamContents: fileStream as: fileNameOnServer
	"FTP a file to the server."


	self binary.
	self openPassiveDataConnection.
	self sendCommand: 'APPE ', fileNameOnServer.

	fileStream reset.
	fileSize := fileStream size.

	[self sendStreamContents: fileStream]
		ensure: [self closeDataSocket].

	self checkResponse.
	self checkResponse.!

ascii
	self sendCommand: 'TYPE A'.
	self lookForCode: 200!

binary
	self sendCommand: 'TYPE I'.
	self lookForCode: 200!

changeDirectoryTo: newDirName
	self sendCommand: 'CWD ' , newDirName.
	self checkResponse.
!

close
		"Close connection."

	self closeDataSocket.
	^super close!

closeDataSocket
	self dataSocket isNil
		ifFalse: [
			self dataSocket disconnect.
			self dataSocket: nil]
!

dataSocket
	^dataSocket!

dataSocket: aSocket
	dataSocket := aSocket!

dataSocketSize

	dataSocket isNil
		ifTrue: [ 0 ]
		ifFalse: [ dataSocket ]!

transferedData

	transferedData isNil
		ifTrue: [ transferedData := (WriteStream on: ByteArray new) ].

	^transferedData!

transferedData: aByteArray
	transferedData := aByteArray!

deleteDirectory: dirName
	self sendCommand: 'RMD ' , dirName.
	self checkResponse.
!

deleteFileNamed: fileName
	self sendCommand: 'DELE ' , fileName.
	self checkResponse.
!

fileSize

	^fileSize!

get: limit dataInto: dataStream
	"Reel in data until the server closes the connection or the limit is reached.
	At the same time, watch for errors on otherSocket."

	| buf bytesRead currentlyRead |
	currentlyRead := 0.
	buf _= String new: 4000.
	[currentlyRead < limit and: 
	[self dataSocket isConnected "or: [self dataSocket dataAvailable]"]]
		whileTrue: [
			"self checkForPendingError."
			bytesRead := self dataSocket receiveAndWaitDataComplete.
			1 to: (bytesRead min: (limit - currentlyRead)) do: [:ii | dataStream nextPut: (buf at: ii)].
			currentlyRead := currentlyRead + bytesRead].
	dataStream reset.	"position: 0."
	^ dataStream!

getData
	"Reel in all data until the server closes the connection.  At the same time, watch for errors on otherSocket.  Don't know how much is coming.  Put the data on the stream."

	| rc byteArray |
	transferedData := nil.

	[ self dataSocket isNil or: [ (rc := self dataSocket primReceiveWithFlags: 0 usingBuffer: self dataSocket buffer) isCommunicationsError
		or: [rc = 0 ] ] ]
		whileFalse: [ self transferedData nextPutAll: (self dataSocket buffer asByteArrayFrom: 0 to: rc - 1) ].

	self checkForPendingError.
	self closeDataSocket.
	byteArray := self transferedData contents.
	transferedData := nil.
	^byteArray!

getDataInto: dataStream
	"Reel in all data until the server closes the connection.  At the same time, watch for errors on otherSocket.  Don't know how much is coming.  Put the data on the stream."

	^(self dataSocket	receiveAndWaitDataComplete)
			buffer asByteArray!

getDirectory
	| dirList |
	self openPassiveDataConnection.
	self sendCommand: 'LIST'.
	dirList := self getData.
	self checkResponse.
	self checkResponse.
	^dirList
!

getFile: remoteFileName
		"Obtiene el archivo remoto."

	| data |
	self openPassiveDataConnection.
	self sendCommand: 'RETR ', remoteFileName.
	[self checkResponse]
		on: Exception
		do: [:ex | self closeDataSocket. Transcript cr; show: 'Error FTP' ].

	data := self getData.
	self checkResponse.
	^data!

getFileNamed: remoteFileName

	| data |

	fileSize := self getFileSize: remoteFileName.
	self binary.
	self openPassiveDataConnection.
	self sendCommand: 'RETR ', remoteFileName.
	[self checkResponse]
		on: Exception
		do: [:ex | self closeDataSocket. Transcript cr; show: 'Error FTP' ].

	[ data := self getData ] fork.
	(Delay forSeconds: 0.2) wait.
	[ self dataSocket isNil ] whileFalse: [
		Transcript cr; show: self transferedData size printString, '/', fileSize printString.
		(Delay forSeconds: 0.1) wait ].

	self checkResponse.
	^data!

getFileNamed: remoteFileName to: fullPath
		"Recupera el archivo y lo guarda en el archivo."

	| file data |
	data := self getFileNamed: remoteFileName.
	file := CfsReadWriteFileStream openEmpty: fullPath.
	file nextPutAll: (data contents).
	file close.!

getFileSize: aFileName

	self sendCommand: 'SIZE ', aFileName.
	self lookForCode: 213.
	^((self lastResponse findTokens: ' ') at: 2) asNumber!

login

	self user isNil ifTrue: [^(AbtError errorText: 'Error FTP. El usuario no puede ser nil')].

	self isConnected ifFalse: [ self connect ].

	self sendCommand: 'USER ', self user.

	"331 Password required"
	self lookForCode: 331.
	"will ask user, if needed"
	self sendCommand: 'PASS ', self password.

	"230 User logged in"
	[ self lookForCode: 230 ]
		whenExceptionDo: [ ^(AbtError errorText: self lastResponse) rc: self responseCode ]!

loginUser: userName password: passwdString

	self user: userName.
	self password: passwdString.

	self login!

openDataSocket: remoteHostAddress port: dataPort

	| connSpec |
	connSpec :=
		AbtTCPConnectionSpec new
			hostId: remoteHostAddress asIPAddress;
			port: dataPort;
			bufferLength: 100;
			blocking: false;
			yourself.

	dataSocket := AbtSocket new.
	dataSocket connectUsing: connSpec.!

openPassiveDataConnection
	| portInfo list dataPort remoteHostAddress |
	self sendCommand: 'PASV'.
	self lookForCode: 227 ifDifferent: [:response | Error signal: ('Could not enter passive mode: ' , response)].

	portInfo := (self lastResponse findTokens: '()') at: 2.
	list := portInfo findTokens: ','.
	remoteHostAddress := ByteArray
		with: (list at: 1) asNumber
		with: (list at: 2) asNumber
		with: (list at: 3) asNumber
		with: (list at: 4) asNumber.
	dataPort := (list at: 5) asNumber * 256 + (list at: 6) asNumber.
	self openDataSocket: remoteHostAddress port: dataPort!

passive
	self sendCommand: 'PASV'.
	self lookForCode: 227!

progressPercentage
	"Answer download progress percentage."

	^(self transferedData size * 100 / self fileSize) asScaledDecimal integerPart asInteger!

putFile: aStream as: fileNameOnServer
	"FTP a file to the server."

	self putFile: aStream as: fileNameOnServer onProgress: nil!

putFile: aStream as: fileNameOnServer onProgress: aProgress
	"FTP a file to the server."

	self openPassiveDataConnection.
	self sendCommand: 'STOR ', fileNameOnServer.

	aStream reset.
	fileSize := aStream size.

	[ [self sendStreamContents: aStream]
		ensure: [self closeDataSocket] ] fork.

	[ self dataSocket isNil ] whileFalse: [
		| percentage |
		percentage := self progressPercentage.
		aProgress isNil ifFalse: [ aProgress fractionComplete: percentage / 100 ].
		(Delay forSeconds: 0.1) wait ].

	self checkResponse.
	self checkResponse.!

putFileNamed: filePath as: fileNameOnServer
	"FTP a file to the server."


	| file rc |
	(file := CfsReadFileStream open: filePath) isCfsError
		ifTrue: [ ^(Error signal: file message)  ].
	rc := (self putFileStreamContents: file as: fileNameOnServer).
	file close.
	^rc!

putFileStreamContents: fileStream as: fileNameOnServer
	"FTP a file to the server."


	self binary.
	self openPassiveDataConnection.
	self sendCommand: 'STOR ', fileNameOnServer.

	fileStream reset.
	fileSize := fileStream size.

	[self sendStreamContents: fileStream]
		ensure: [self closeDataSocket].

	self checkResponse.
	self checkResponse.!

pwd
	| result |
	self sendCommand: 'PWD'.
	self lookForCode: 257.
	result := self lastResponse.
	^result copyFrom: (result indexOf: $")+1 to: (result lastIndexOf: $")-1!

quit
	self sendCommand: 'QUIT'.
	self close!

sendStreamContents: aStream

	| socketStream bufferSize q |
	socketStream := AbtSocketStream on: self dataSocket sciSocket.
	bufferSize := 4000.
	[ aStream atEnd ] whileFalse: [
		| partial |
		partial := (aStream size - aStream position) > bufferSize
			ifTrue: [ aStream next: bufferSize ]
			ifFalse: [ aStream upToEnd ].
		self transferedData nextPutAll: partial.
		socketStream	nextPutAll: partial.
		socketStream	flush ].
	socketStream close.
	transferedData := nil.! !

FTPClient initializeAfterLoad!


NetClient subclass: #TelnetClient
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!TelnetClient class publicMethods !

defaultPortNumber
	^23! !

TelnetClient initializeAfterLoad!


Object subclass: #ShaEngine
    instanceVariableNames: 'aa bb cc dd ee w count '
    classVariableNames: ''
    poolDictionaries: ''!

!ShaEngine publicMethods !

countMask

	^64 - 1!

digest: bytes

	self reset.
	self updateBytes: bytes.
	^self engineDigest!

engineDigest

	| result bits |
	bits := count bitShift: 3.
	self updateBytes: #[16r80] from: 1.
	[(count bitAnd: self countMask) ~= 56] whileTrue: [self updateBytes: #[16r0] from: 1].

	w at: 15 put: (bits sshBit32Shift: -32).
	w at: 16 put: (bits bitAnd: 16rFFFFFFFF).

	count := count + 8.
	self processBlock.

	result := Array new: 20.
	result at: 1 put: ((aa sshBit32Shift: -24) bitAnd: 255).
	result at: 2 put: ((aa sshBit32Shift: -16) bitAnd: 255).
	result at: 3 put: ((aa sshBit32Shift: -8) bitAnd: 255).
	result at: 4 put: (aa bitAnd: 255).

	result at: 5 put: ((bb sshBit32Shift: -24) bitAnd: 255).
	result at: 6 put: ((bb sshBit32Shift: -16) bitAnd: 255).
	result at: 7 put: ((bb sshBit32Shift: -8) bitAnd: 255).
	result at: 8 put: (bb bitAnd: 255).

	result at: 9 put: ((cc sshBit32Shift: -24) bitAnd: 255).
	result at: 10 put: ((cc sshBit32Shift: -16) bitAnd: 255).
	result at: 11 put: ((cc sshBit32Shift: -8) bitAnd: 255).
	result at: 12 put: (cc bitAnd: 255).

	result at: 13 put: ((dd sshBit32Shift: -24) bitAnd: 255).
	result at: 14 put: ((dd sshBit32Shift: -16) bitAnd: 255).
	result at: 15 put: ((dd sshBit32Shift: -8) bitAnd: 255).
	result at: 16 put: (dd bitAnd: 255).

	result at: 17 put: ((ee sshBit32Shift: -24) bitAnd: 255).
	result at: 18 put: ((ee sshBit32Shift: -16) bitAnd: 255).
	result at: 19 put: ((ee sshBit32Shift: -8) bitAnd: 255).
	result at: 20 put: (ee bitAnd: 255).

	self reset.
	^result!

reset

	aa := 16r67452301.
	bb := 16rEFCDAB89.
	cc := 16r98BADCFE.
	dd := 16r10325476.
	ee := 16rC3D2E1F0.
	w := (Array new: 80) atAllPut: 0.
	count := 0!

updateBytes: bytes

	| index stop |
	1
		to: (stop := bytes size - (bytes size \\ 4))
		by: 4
		do: [:i |
			index := (count bitAnd: self countMask) bitShift: -2.
			w
				at: index + 1
				put: (
					((bytes at: i) bitShift: 24) + ((bytes at: i + 1) bitShift: 16) +
						((bytes at: i + 2) bitShift: 8) + (bytes at: i + 3)).
			count := count + 4.
			(count bitAnd: self countMask) = 0 ifTrue: [self processBlock]].
	self updateBytes: bytes from: stop + 1!

updateBytes: bytes from: start

	start to: bytes size do: [:i | | index offset value |
		index := ((count bitAnd: self countMask) bitShift: -2 ) + 1.
		offset := (count bitInvert bitAnd: 3) bitShift: 3.
		value := ((w at: index) bitAnd: (16rFF bitShift: offset) bitInvert)
			bitOr: ((bytes at: i) bitShift: offset).
		w at: index put: value.
		(count bitAnd: self countMask) = self countMask ifTrue: [self processBlock].
		count := count + 1]! !

!ShaEngine privateMethods !

processBlock

	| a b c d e temp |
	17 to: 80 do: [:t |
		temp := (((w at: t - 3) bitXor: (w at: t - 8)) bitXor: (w at: t - 14)) bitXor: (w at: t - 16).
		w at: t put: ((temp sshBit32Shift: 1) bitOr: (temp sshBit32Shift: -31))].

	a := aa.
	b := bb.
	c := cc.
	d := dd.
	e := ee.

	1 to: 20 do: [:i |
		temp := (((a sshBit32Shift: 5) bitOr: (a sshBit32Shift: -27)) +
			((b bitAnd: c) bitOr: (b bitInvert bitAnd: d)) + e + (w at: i) + self round1_kt)
				bitAnd: 16rFFFFFFFF.
		e := d.
		d := c.
		c := (b sshBit32Shift: 30) bitOr: (b sshBit32Shift: -2).
		b := a.
		a := temp].

	21 to: 40 do: [:i |
		temp := (((a sshBit32Shift: 5) bitOr: (a sshBit32Shift: -27)) + ((b bitXor: c) bitXor: d) + e +
			(w at: i) + self round2_kt)
				bitAnd: 16rFFFFFFFF.
		e := d.
		d := c.
		c := (b sshBit32Shift: 30) bitOr: (b bitShift: -2).
		b := a.
		a := temp].

	41 to: 60 do: [:i |
		temp := (((a sshBit32Shift: 5) bitOr: (a sshBit32Shift: -27)) +
			(((b bitAnd: c) bitOr: (b bitAnd: d)) bitOr: (c bitAnd: d)) + e + (w at: i) +
			self round3_kt)
				bitAnd: 16rFFFFFFFF.
		e := d.
		d := c.
		c := (b sshBit32Shift: 30) bitOr: (b sshBit32Shift: -2).
		b := a.
		a := temp].

	61 to: 80 do: [:i |
		temp := (((a sshBit32Shift: 5) bitOr: (a sshBit32Shift: -27)) + ((b bitXor: c) bitXor: d) + e +
			(w at: i) + self round4_kt)
				bitAnd: 16rFFFFFFFF.
		e := d.
		d := c.
		c := (b sshBit32Shift: 30) bitOr: (b sshBit32Shift: -2).
		b := a.
		a := temp].

	aa := aa + a.
	bb := bb + b.
	cc := cc + c.
	dd := dd + d.
	ee := ee + e!

round1_kt

	^16r5A827999!

round2_kt

	^16r6ED9EBA1!

round3_kt

	^16r8F1BBCDC!

round4_kt

	^16rCA62C1D6! !

ShaEngine initializeAfterLoad!


Object subclass: #SSH2Connector
    instanceVariableNames: 'hostName portNumber sessionId errors exchangeHash socketStream state sendSequenceNumber getSequenceNumber keyExchangeAlgorithm encryptionAlgorithm decryptionAlgorithm compressionAlgorithm decompressionAlgorithm hmacCheckAlgorithm hmacCreateAlgorithm encryptionEnabled channelStatus channelBuffers serverChannels packetSizesClientToServer windowSizesClientToServer generator randomValueForKey clientConfiguration serverConfiguration '
    classVariableNames: ''
    poolDictionaries: 'SSH2Constants '!

!SSH2Connector class publicMethods !

basicNew
	"Answer a new instance of the receiver."

	^super basicNew 
		initialize!

initializePoolDictionary

	Smalltalk 
		at: #SSH2Constants
		put: (EsPoolDictionary new 
			"Connection constants."
				at: 'SSH_CHANNEL_EXEC' put: 0; 
				at: 'SSH_CHANNEL_SHELL' put: 1;
				at: 'SSH_READ_SIMPLE' put: 1;
				at: 'SSH_READ_REGEX' put: 2;
			"Channel open failure constants."
				at: 'SSH_OPEN_ADMINISTRATIVELY_PROHIBITED' put: 1;
			"Disconnect reasons."
				at: 'SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT' put: 1;
				at: 'SSH_DISCONNECT_PROTOCOL_ERROR' put: 2;
				at: 'SSH_DISCONNECT_KEY_EXCHANGE_FAILED' put: 3;
				at: 'SSH_DISCONNECT_RESERVED' put: 4;
				at: 'SSH_DISCONNECT_MAC_ERROR' put: 5;
				at: 'SSH_DISCONNECT_COMPRESSION_ERROR' put: 6;
				at: 'SSH_DISCONNECT_SERVICE_NOT_AVAILABLE' put: 7;
				at: 'SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED' put: 8;
				at: 'SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE' put: 9;
				at: 'SSH_DISCONNECT_CONNECTION_LOST' put: 10;
				at: 'SSH_DISCONNECT_BY_APPLICATION' put: 11;
				at: 'SSH_DISCONNECT_TOO_MANY_CONNECTIONS' put: 12;
				at: 'SSH_DISCONNECT_AUTH_CANCELLED_BY_USER' put: 13;
				at: 'SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE' put: 14;
				at: 'SSH_DISCONNECT_ILLEGAL_USER_NAME' put: 15;
			"Message constants."
				at: 'SSH_EXTENDED_DATA_STDERR' put: 1;
			"Channel open failure constants."
				at: 'SSH_MSG_DISCONNECT' put: 1;
				at: 'SSH_MSG_IGNORE' put: 2;
				at: 'SSH_MSG_UNIMPLEMENTED' put: 3;
				at: 'SSH_MSG_DEBUG' put: 4;
				at: 'SSH_MSG_SERVICE_REQUEST' put: 5;
				at: 'SSH_MSG_SERVICE_ACCEPT' put: 6;
				at: 'SSH_MSG_KEXINIT' put: 20;
				at: 'SSH_MSG_NEWKEYS' put: 21;
				at: 'SSH_MSG_KEXDH_INIT' put: 30;
				at: 'SSH_MSG_KEXDH_REPLY' put: 31;
				at: 'SSH_MSG_USERAUTH_REQUEST' put: 50;
				at: 'SSH_MSG_USERAUTH_FAILURE' put: 51;
				at: 'SSH_MSG_USERAUTH_SUCCESS' put: 52;
				at: 'SSH_MSG_USERAUTH_BANNER' put: 53;
				at: 'SSH_MSG_GLOBAL_REQUEST' put: 80;
				at: 'SSH_MSG_REQUEST_SUCCESS' put: 81;
				at: 'SSH_MSG_REQUEST_FAILURE' put: 82;
				at: 'SSH_MSG_CHANNEL_OPEN' put: 90;
				at: 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION' put: 91;
				at: 'SSH_MSG_CHANNEL_OPEN_FAILURE' put: 92;
				at: 'SSH_MSG_CHANNEL_WINDOW_ADJUST' put: 93;
				at: 'SSH_MSG_CHANNEL_DATA' put: 94;
				at: 'SSH_MSG_CHANNEL_EXTENDED_DATA' put: 95;
				at: 'SSH_MSG_CHANNEL_EOF' put: 96;
				at: 'SSH_MSG_CHANNEL_CLOSE' put: 97;
				at: 'SSH_MSG_CHANNEL_REQUEST' put: 98;
				at: 'SSH_MSG_CHANNEL_SUCCESS' put: 99;
				at: 'SSH_MSG_CHANNEL_FAILURE' put: 100;
			"Terminal modes constants."
				at: 'SSH_TTY_OP_END' put: 0;
			yourself)!

new
	"Answer a new instance of the receiver."

	^self error: 'Can´t construct with new'!

onHost: hostName port: portNumber
	"Answer a new instance of the receiver on <hostName> and <portNumber>."

	^self basicNew
		hostName: hostName;
		portNumber: portNumber;
		yourself!

startupOnHost: hostName port: portNumber
	"Answer a new connected instance of the receiver on <hostName> and <portNumber>."

	^(self onHost: hostName port: portNumber)
		startup;
		yourself! !

!SSH2Connector publicMethods !

byteFromBinary: aString

	| value |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		each = $1 ifTrue: [value := value + (2 raisedTo: index - 1)]].
	^value asCharacter!

check: anObject type: anInteger errorMessage: aString
	"Verify whether <anObject> type is <anInteger>. 
	 When false, signals an error with <aString> description."

	anObject type = anInteger
		ifFalse: [self error: aString]
!

checkConnectionActive
	"Check whether the receiver connection is active. Signals an error if not."

	socketStream atEnd ifTrue: [self error: 'Connection closed by server']





!

checkServerHostKeyAlgorithms
	"Check whether the server host keys are compatible."

	serverConfiguration checkServerHostKeyAlgorithms: clientConfiguration!

close
	"Close the receiver connection."

	self disconnect
!

connectSocket
	"Connect the socket of the receiver."

	socketStream := AbtSocketStream createClientSocketToHost: self hostName port: self portNumber.
	socketStream lastError ifNotNil: [:value | self error: value message]
!

createCookie 
	"Answer a 16 byte random string cookie."

	^(1 to: 16) inject: '' into: [:total :each | total, self randomValue asCharacter asString]
!

decryptBlockSize
	"Answer decrypt block size parameter."

	^8!

describeString: aString
	"Answer a binary representation for <aString>."

	^(self integerToString: aString size), aString


!

determineEncryptionAlgorithms
	"Establish a encryption algorithm for the receiver."

	encryptionAlgorithm := clientConfiguration compatibleEncryptionAlgorithm: serverConfiguration.
	decryptionAlgorithm := clientConfiguration compatibleDecryptionAlgorithm: serverConfiguration

!

determineHMACAlgorithms
	"Establish HMAC creation and HMAC check algorithms for the receiver."

	hmacCreateAlgorithm := clientConfiguration compatibleHMACCreateAlgorithm: serverConfiguration.
	hmacCheckAlgorithm := clientConfiguration compatibleHMACCheckAlgorithm: serverConfiguration


!

determineKeyExchangeAlgorithm
	"Establish a key exchange algorithm for the receiver."

	keyExchangeAlgorithm := clientConfiguration compatibleKeyExchangeAlgorithm: serverConfiguration!

disconnect
	"Disconnect the receiver."

	self disconnect: SSH_DISCONNECT_BY_APPLICATION!

disconnect: anInteger
	"Close the receiver connection with reason <anInteger>."

	state isNil ifFalse: [	
		self sendBinary: (SSH2Message messageDisconnectReason: anInteger).
		state := nil.
		socketStream close]!

encryptBlockSize
	"Answer encrypt block size parameter."

	^8!

encryptionKeyLength
	"Answer a key length suitable for the receiver."

	^(encryptionAlgorithm keyLength max: decryptionAlgorithm keyLength) 
			min: 160!

exchangeKeys
	"Perform the key exchange process. "

	self
		sendKeyExchangeInit;
		determineEncryptionAlgorithms;
		determineKeyExchangeAlgorithm;
		sendKeys;
		readKeyExchangeDHReply;
		initializeExchangeHash;
		checkServerHostKeyAlgorithms;
		sendNewKeys;
		readNewKeys;
		initializeEncryption;
		determineHMACAlgorithms;
		initializeHMAC;
		initializeCompression
	
!

executeCommand: aString
	"Execute <aString> shell command, answer results."	

	| value output |
	self 
		sendChannelOpen: SSH_CHANNEL_EXEC;
		getChannelPacket: SSH_CHANNEL_EXEC;
		sendChannelRequest: aString;
		getChannelPacket: SSH_CHANNEL_EXEC.

	channelStatus at: SSH_CHANNEL_EXEC put: SSH_MSG_CHANNEL_DATA.
	output := ReadWriteStream on: ''.
	[(value := (self getChannelPacket: SSH_CHANNEL_EXEC)) = true]	
		whileFalse: [
			value = false ifTrue: [self error: 'Receive error'].
			output nextPutAll: value].
	^output contents
		
	!

filter: aString
	"Filter messages that should be discarded and perform extra processing for some messages."

	| value returnValue |
	returnValue := aString.
	value := aString first asInteger.
	(value = SSH_MSG_KEXINIT) ifTrue: [
	 	sessionId isNil ifFalse: [
  		self reExchangeKeys: returnValue.
			state := nil.
	    returnValue := self getBinary]].
	
	(state = ##logged) ifTrue: [
		value = SSH_MSG_CHANNEL_WINDOW_ADJUST ifTrue: [
			returnValue := self getBinary]].

	^returnValue!

get
	"Answer a new message sent by the server."	

	| value |
	(value := self getBinary) isEmpty 
		ifTrue: [self error: 'Connection closed by server'].
	^self messajeFrom: value!

getBinary
	"Answer the binary message sent by the server."	

	| raw value buffer remainingLength packetLength padding paddingLength payLoad |
	self checkConnectionActive.
	raw := socketStream next: self decryptBlockSize.
	raw isEmpty ifTrue: [^value].
	encryptionEnabled ifTrue: [raw := decryptionAlgorithm decrypt: raw].

	packetLength := raw sshLongAt: 1.
	paddingLength := (raw at: 5) value.
	raw := raw copyFrom: 6 to: raw size.
	remainingLength := packetLength + 4 - 8.
	buffer := ReadWriteStream on: ''.

	[remainingLength > 0]	whileTrue: [
			value := socketStream next: remainingLength.
			buffer nextPutAll: value.
			remainingLength := remainingLength - value size].

	buffer contents isEmpty ifFalse: [
		raw := raw, (encryptionEnabled 
									ifTrue: [decryptionAlgorithm decrypt: buffer contents] 
									ifFalse: [buffer contents])].	
	payLoad := raw copyFrom: 1 to: packetLength - paddingLength - 1.
	padding := raw copyFrom: packetLength - paddingLength to: raw size. 

	hmacCheckAlgorithm notNil ifTrue: [
		| hmac message |
		hmac := socketStream next: hmacCheckAlgorithm keyLength.
		message := (ReadWriteStream on: '')
									nextPutAll: (self integerToString: getSequenceNumber);
									nextPutAll: (self integerToString: packetLength);
									nextPut: paddingLength asCharacter;
									nextPutAll: payLoad;
									nextPutAll: padding;
									contents.
		hmac = (hmacCheckAlgorithm hash: message)
			ifFalse: [self error: 'Invalid HMAC']].

	getSequenceNumber := getSequenceNumber + 1.
	^self filter: payLoad


!

getChannelPacket: aNumber

	| value status message |
	[true] whileTrue: [
		value := self getBinary.
		value isEmpty ifTrue: [^value].
		message := SSH2Message fromBytes: value.

		status := channelStatus at: aNumber.
		status = SSH_MSG_CHANNEL_OPEN ifTrue: [
			message type = SSH_MSG_CHANNEL_OPEN_CONFIRMATION ifTrue: [
				serverChannels at: aNumber put: message serverChannel.
				packetSizesClientToServer at: aNumber put: message packetSize.
				^true].
			self error: 'Unable to open channel'].

		status = SSH_MSG_CHANNEL_REQUEST ifTrue: [
			message type = SSH_MSG_CHANNEL_SUCCESS ifTrue: [^true].
			self error: 'Unable to request a pseudo-terminal'].

		message type = SSH_MSG_CHANNEL_DATA ifTrue: [
			message channel = aNumber ifTrue: [^message data].
			channelBuffers at: aNumber ifAbsentPut: [OrderedCollection new].
			(channelBuffers at: aNumber) add: message data].

		message type = SSH_MSG_CHANNEL_EXTENDED_DATA ifTrue: [
			message channel = aNumber ifTrue: [^message data].
			channelBuffers at: aNumber ifAbsentPut: [OrderedCollection new].
			(channelBuffers at: aNumber) add: message data].

		message type = SSH_MSG_CHANNEL_REQUEST ifTrue: [
			message requestType = 'exit-signal' ifTrue: [
			self logError: 'SSH_MSG_CHANNEL_REQUEST (exit-signal): ' value: message specific]].

		message type = SSH_MSG_CHANNEL_CLOSE ifTrue: [
			self sendChannelClose: aNumber.
			^true].

		((OrderedCollection new 
			add: SSH_MSG_CHANNEL_DATA;
			add: SSH_MSG_CHANNEL_EXTENDED_DATA;
			add: SSH_MSG_CHANNEL_REQUEST;
			add: SSH_MSG_CHANNEL_CLOSE;
			add: SSH_MSG_CHANNEL_EOF;
			yourself)
				includes: message type)
				ifFalse: [self error: 'Error reading channel data']]
	
	!

hash: aString
	"Answer <aString> hashed by SHA1 hash function."

	^String withAll: ((ShaEngine new digest: aString asByteArray)
											collect: [:each | each asCharacter])!

hmacKeyLength
	"Answer a key length suitable for the receiver."

	^20!

hostName
	
	^hostName!

hostName: aString
	
	hostName := aString!

initialize
	"Initialize the receiver."

	errors := OrderedCollection new.
	generator := EsRandom new.
	clientConfiguration := SSHHostConfiguration defaultIdentified: 'SSH-2.0-vastseclib_0.2' cookie: self createCookie.
	serverConfiguration := SSHHostConfiguration new.
	getSequenceNumber := 0.
	sendSequenceNumber := 0.
	encryptionEnabled := false.
	channelStatus := Dictionary new.
	channelBuffers := Dictionary new.
	serverChannels := Dictionary new.
	packetSizesClientToServer := Dictionary new.
	windowSizesClientToServer := Dictionary new.
	randomValueForKey := (generator next * (2 raisedTo: 32) + 6666) asInteger
 !

initializeCompression
	"Initialize compression algorithms of the receiver."

	compressionAlgorithm := clientConfiguration compatibleCompressionAlgorithm: serverConfiguration.
	decompressionAlgorithm := clientConfiguration compatibleDecompressionAlgorithm: serverConfiguration


!

initializeEncryption
	"Initializes encryption algorithms of the receiver."

	| key newKey |
	newKey := self describeString: clientConfiguration privateKey.

	"Initialize encryption settings."
	key := self hash: newKey, exchangeHash, 'C', sessionId.
	[encryptionAlgorithm defaultKeyLength > key size] whileTrue: [
		key := key, (self hash: newKey, exchangeHash, key)].
	encryptionAlgorithm 
			key: (key copyFrom: 1 to: encryptionAlgorithm defaultKeyLength); 
			encrypt: (String withAll: ((1 to: 1536) collect: [:each | 0 asCharacter])).

	"Initialize decryption settings."
	key := self hash: newKey, exchangeHash, 'D', sessionId.
	[decryptionAlgorithm defaultKeyLength > key size] whileTrue: [
		key := key, (self hash: newKey, exchangeHash, key)].
	decryptionAlgorithm 
			key: (key copyFrom: 1 to: decryptionAlgorithm defaultKeyLength); 
			decrypt: (String withAll: ((1 to: 1536) collect: [:each | 0 asCharacter]))


!

initializeExchangeHash
	"Initializes exchange hash of the receiver connection."

	exchangeHash :=
		((ReadWriteStream on: '')
			nextPutAll: (self describeString: clientConfiguration identifier);
			nextPutAll: (self describeString: serverConfiguration identifier);
			nextPutAll: (self describeString: clientConfiguration kexInitPayload);
			nextPutAll: (self describeString: serverConfiguration kexInitPayload);
			nextPutAll: (self describeString: serverConfiguration publicKeyData);
			nextPutAll: (self describeString: clientConfiguration publicKey);
			nextPutAll: (self describeString: serverConfiguration publicKey);
			nextPutAll: (self describeString: clientConfiguration privateKey);
			yourself)
				contents.

	exchangeHash := self hash: exchangeHash.
	sessionId := exchangeHash!

initializeHMAC
	"Initializes HMAC algorithms of the receiver."

	| key newKey |
	newKey := self describeString: clientConfiguration privateKey.

	"Initialize HMAC creation."
	key := self hash: newKey, exchangeHash, 'E', sessionId.
	[self hmacKeyLength > key size] whileTrue: [
		key := key, (self hash: newKey, exchangeHash, key)].
	hmacCreateAlgorithm key: (key copyFrom: 1 to: self hmacKeyLength). 

	"Initialize HMAC check."
	key := self hash: newKey, exchangeHash, 'F', sessionId.
	[self hmacKeyLength > key size] whileTrue: [
		key := key, (self hash: newKey, exchangeHash, key)].
	hmacCheckAlgorithm key: (key copyFrom: 1 to: self hmacKeyLength)!

integerToString: anInteger
	"Answer a string representing <anInteger> in little endian format, padded to 32 bits."

	^self integerToString: anInteger bits: 32!

integerToString: anInteger bits: aNumber
	"Answer a string representing <anInteger> in little endian format, padded to <aNumber> bits."

	| stream index binary |
	binary := ''.
	stream := ReadWriteStream on: ''.
	index := 0.

	(anInteger printStringRadix: 2 padTo: aNumber) reverse do: [:each | 
		index := index + 1.
		binary := binary, each asString.
		index = 8 ifTrue: [
			index := 0. 
			stream nextPut: (self byteFromBinary: binary reverse).
			binary := '' ]].

	index > 0 ifTrue: [
		1 to: 8 - index do: [:each | binary := $0 asString, binary].
		stream nextPut: (self byteFromBinary: binary)].
	
	^stream contents reverse
	!

isServerIdentifier: aString

	^'SSH-*-*' match: aString


!

logError: anObject value: aString
	"Log a status error for <anObject> and <aString> description."

	errors add: anObject -> aString.
	self error: aString

!

login: username password: password
	"Login the receiver with <username> and <password>."

	state = ##initialized ifFalse: [self error: 'Not connected'].
	self 
		sendLoginRequest;
		check: self get type: SSH_MSG_SERVICE_ACCEPT errorMessage: 'Expected SSH_MSG_SERVICE_ACCEPT';
		sendUserAuthorization: username password: password;
		check: self get type: SSH_MSG_USERAUTH_SUCCESS errorMessage: 'Expected SSH_MSG_USERAUTH_SUCCESS'.
	state := ##logged

!

messajeFrom: aString
	"Answer a new SSH2message instance built from <aString>."

	^SSH2Message fromBytes: aString

	!

portNumber
	
	^portNumber!

portNumber: anInteger
	
	portNumber := anInteger!

randomValue
	"Answer a random integer value in range [0, 255]."

	^(generator next * 255) asInteger!

readKeyExchangeDHReply

	| value |	
	value := self get.
	self check: value type: SSH_MSG_KEXDH_REPLY errorMessage: 'Expected SSH_MSG_KEXDH_REPLY'.
	serverConfiguration configureFromDHReply: value.
	"Calculate new key."
	clientConfiguration privateKey: (keyExchangeAlgorithm createNewKeyFor: serverConfiguration publicKey randomValue: randomValueForKey)
!

readNewKeys

	self check: self get type: SSH_MSG_NEWKEYS errorMessage: 'Expected SSH_MSG_NEWKEYS'!

readServerIdentifier

	| value extraLines |
	"#TODO: Register the FTP extra lines - SEE EDITIONS."
	extraLines := OrderedCollection new.
	[socketStream atEnd or: [self isServerIdentifier: value]] whileFalse: [	
		value := socketStream nextLineCrOrLf.
		extraLines add: value].
	serverConfiguration identifier: value
!

reExchangeKeys: response
	"Perform the key exchange process. "

	serverConfiguration configureFromKeyExchangeInit: response.
	self exchangeKeys


!

registerServerData
	"Register data sent by KEXINIT message on receiver serverConfiguration."

	| response |
	response := self get.
	self check: response type: SSH_MSG_KEXINIT errorMessage: 'Expected SSH_MSG_KEXINIT'.
	serverConfiguration configureFromKeyExchangeInit: response!

send: aSSH2Message
	"Send <aSSH2Message> to server host."

	^self sendBinary: aSSH2Message contents!

sendBinary: aCollection
	"Send binary data on <aCollection> to server host."

	| packet packetLength paddingLength padding hmac |
	self checkConnectionActive.
	packetLength := aCollection size + 9.
	packetLength :=	packetLength + (((self encryptBlockSize - 1) * packetLength) \\ self encryptBlockSize).
	
	"Add random padding."
	paddingLength := packetLength - aCollection size - 5.
	padding := ''.	
	paddingLength timesRepeat: [padding := (padding ifNil: ['']), self randomValue asCharacter asString].

	packet := (self integerToString: packetLength - 4),
						paddingLength asCharacter asString,
						aCollection,
						padding.

	"Calculate HMAC hash."
	hmac := hmacCreateAlgorithm isNil
		ifTrue: ['']
		ifFalse: [hmacCreateAlgorithm hash: (self integerToString: sendSequenceNumber), packet].	
 
	sendSequenceNumber := sendSequenceNumber + 1.
	encryptionEnabled ifTrue: [packet := encryptionAlgorithm encrypt: packet].
	^socketStream nextPutAll: packet, hmac; flush


	!

sendChannelClose: aNumber
	"Send close message for channel <aNumber> to server host."

	self send: (SSH2Message messageCloseChannel: (serverChannels at: aNumber))


!

sendChannelOpen: aNumber
	"Send open message for channel <aNumber> to server host."

	self send: (SSH2Message messageOpenChannelSession: aNumber windowSize: self windowSize packetSize: 16384).
	channelStatus at: aNumber put: SSH_MSG_CHANNEL_OPEN

!

sendChannelRequest: command
	"Send request message for <command> on channel SSH_CHANNEL_EXEC to server host."

	self send: (SSH2Message messageChannelRequest: SSH_CHANNEL_EXEC command: command).
	channelStatus at: SSH_CHANNEL_EXEC put: SSH_MSG_CHANNEL_REQUEST!

sendKeyExchangeInit
	"Send key exchange init message to server host."

	self send: clientConfiguration messageForKeyExchange
	

!

sendKeys
	"Send key exchange dh init message to server host."

	clientConfiguration publicKey: (keyExchangeAlgorithm generateKey: self encryptionKeyLength x: randomValueForKey).
	self send: (SSH2Message messageKeyExchangeDHInit: clientConfiguration publicKey)
!

sendLoginRequest
	"Send login request message to server host."

	self send: SSH2Message messageSSHLoginRequest


	

	

	
!

sendNewKeys
	"Send new key message to server host."

	self send: SSH2Message messageNewKeys
!

sendString: aString
	"Send <aString> binary message to server host."

	socketStream
		nextPutAll: aString;
		nextPut: Character lf;
		flush!

sendUserAuthorization: username password: password
	"Send user authorization request message to server host for <username> and <password>."

	self send: (SSH2Message messageAuthorizationRequestUser: username password: password)

	
	

	

	
!

setInitialized
	"Finalize conection startup process of the receiver."

	state := ##initialized.
	encryptionEnabled := true
!

startup
	"Start up the connection of the receiver."

	self 
		connectSocket;
		readServerIdentifier;
		checkConnectionActive;
		validateServerIdentifier;
		sendString: clientConfiguration identifier;
		registerServerData;
		exchangeKeys;
		setInitialized





!

validateServerIdentifier
	"Validates server identifier. Signal an error if not valid."

	serverConfiguration identifier trimBlanks isEmpty
		ifTrue: [self error: 'Server identification failed'].

	(('SSH-2.0-*' match: serverConfiguration identifier) or: 
		['SSH-1.99-*' match: serverConfiguration identifier])
			ifFalse: [self error: 'Server version not compatible'].		
!

windowSize
	"Answer the maximum window size parameter of the receiver."

	^2147483647! !

SSH2Connector initializeAfterLoad!


SSH2Connector subclass: #SFTPClient
    instanceVariableNames: 'packetBuffer requestId extensions version pwd '
    classVariableNames: ''
    poolDictionaries: 'SFTPConstants '!

!SFTPClient class publicMethods !

initializePoolDictionary

	Smalltalk 
		at: #SFTPConstants
		put: (EsPoolDictionary new 
			at: 'SSH_FXP_CHANNEL' put: 2;
		"Commands constants"
			at: 'SSH_FXP_INIT' put: 1;
			at: 'SSH_FXP_VERSION' put: 2;
			at: 'SSH_FXP_OPEN' put: 3;
			at: 'SSH_FXP_CLOSE' put: 4;
			at: 'SSH_FXP_READ' put: 5;
			at: 'SSH_FXP_WRITE' put: 6;
			at: 'SSH_FXP_LSTAT' put: 7;
			at: 'SSH_FXP_SETSTAT' put: 9;
			at: 'SSH_FXP_OPENDIR' put: 11;
			at: 'SSH_FXP_READDIR' put: 12;
			at: 'SSH_FXP_REMOVE' put: 13;
			at: 'SSH_FXP_MKDIR' put: 14;
			at: 'SSH_FXP_RMDIR' put: 15;
			at: 'SSH_FXP_REALPATH' put: 16;
			at: 'SSH_FXP_STAT' put: 17;
			at: 'SSH_FXP_RENAME' put: 18;
			at: 'SSH_FXP_STATUS' put: 101;
			at: 'SSH_FXP_HANDLE' put: 102;
			at: 'SSH_FXP_DATA' put: 103;
			at: 'SSH_FXP_NAME' put: 104;
			at: 'SSH_FXP_ATTRS' put: 105;
			at: 'SSH_FXP_EXTENDED' put: 200;
		"Status constants"
			at: 'SSH_FXP_STATUS_OK' put: 0;
			at: 'SSH_FXP_STATUS_EOF' put: 1;
			at: 'SSH_FXP_STATUS_NO_SUCH_FILE' put: 2;
			at: 'SSH_FXP_STATUS_PERMISSION_DENIED' put: 3;
			at: 'SSH_FXP_STATUS_FAILURE' put: 4;
			at: 'SSH_FXP_STATUS_BAD_MESSAGE' put: 5;
			at: 'SSH_FXP_STATUS_NO_CONNECTION' put: 6;
			at: 'SSH_FXP_STATUS_CONNECTION_LOST' put: 7;
			at: 'SSH_FXP_STATUS_OP_UNSUPPORTED'put: 8;
		"Attributes flag constants"
			at: 'SSH_FXP_ATTR_SIZE' put: 1;
			at: 'SSH_FXP_ATTR_UIDGID' put: 2;
			at: 'SSH_FXP_ATTR_PERMISSIONS'  put: 4;
			at: 'SSH_FXP_ATTR_ACCESSTIME'  put: 8;
		"Open flag constants"
			at: 'SSH_FXP_OPEN_READ'  put: 1;
			at: 'SSH_FXP_OPEN_WRITE'  put: 2;
			at: 'SSH_FXP_OPEN_CREATE'  put: 8;
			at: 'SSH_FXP_OPEN_TRUNCATE' put: 10;
		"Type flag constants"
			at: 'SSH_FXP_TYPE_REGULAR' put: 1;
			at: 'SSH_FXP_TYPE_DIRECTORY' put: 2;
			at: 'SSH_FXP_TYPE_SYMLINK' put: 3;
			at: 'SSH_FXP_TYPE_SPECIAL' put: 4;
			yourself)! !

!SFTPClient publicMethods !

baseName: aString
	"Answer the file name of path name in <aString>."

	^aString!

changeDirectory: aString
	"Set current directory of the receiver to <aString>."

	| dir response handle |
	dir := aString.
	dir first ~= $/ ifTrue: [dir := dir, '/'].
	dir := self realPath: dir.
	self sendSFTP: (SFTPMessage messageOpenDir: dir).
	response := self getSFTP.
	handle := self processHandleRequest: response.
	self sendSFTP: (SFTPMessage messageCloseHandle: response handle).
	response := self getSFTP.
	self processStatusRequestOk: response.
	pwd := dir.
	^true


!

checkWindowAdjust: windowSize channel: aNumber
	"Check whether window adjust should be done and performs it if so."

	(windowSizesClientToServer at: aNumber) < 0	ifTrue: [
		self send: (SSH2Message messageWindowAdjust: (serverChannels at: aNumber) size: windowSize).
		windowSizesClientToServer at: aNumber put: (windowSizesClientToServer at: aNumber) + windowSize]




	
	
	!

dirName: aString
	"Answer the directory name of path name in <aString>."

	^'.'!

getFile: aString
	"Answer a string with file contents refered by <aString>."

	^self getFile: aString progress: [:object | ]
	
	
	
!

getFile: aString in: localPath
	"Write a file in <localPath> with file contents refered by <aString>."

	| file |
	[(file := CfsWriteFileStream open: localPath)
			nextPutAll: (self getFile: aString);
			flush] ensure: [file close]


!

getFile: aString in: localPath progress: aMonadicValuable
	"Write a file in <localPath> with file contents refered by <aString>.
	Updates <aProgress> value while downloading."

	| file |
	[(file := CfsWriteFileStream open: localPath)
			nextPutAll: (self getFile: aString progress: aMonadicValuable);
			flush] ensure: [file close]!

getFile: aString progress: aMonadicValuable
	"Answer a string with file contents refered by <aString>.
	Updates <aMonadicValuable> value while downloading."

	| size remoteFile file handle |
	remoteFile := self realPath: aString.
	size := self remoteFileSize: remoteFile.
	self sendChannelRead: remoteFile.
	handle := self processHandleRequest: self getSFTP.
	file := self readFile: handle size: size progress: aMonadicValuable.
	self sendClose: handle.
	^file
	
	
	
!

getSFTP
	"Read and answer a SFTPMessage instance from server host."

	| temp length tempLength packet result |
	[packetBuffer size < 4] whileTrue: [
		temp := self getChannelPacket: SSH_FXP_CHANNEL.
		temp = true ifTrue: [packetBuffer := ''. ^false].
		packetBuffer := packetBuffer, temp].

	length := packetBuffer sshLongAt: 1.
	packetBuffer := packetBuffer copyFrom: 5 to: packetBuffer size.
	tempLength := length - packetBuffer size.

	[tempLength > 0] whileTrue: [
		temp := self getChannelPacket: SSH_FXP_CHANNEL.
		temp = true ifTrue: [packetBuffer := ''. ^false].
		packetBuffer := packetBuffer, temp.
		tempLength := tempLength - temp size].

	result := packetBuffer copyFrom: 1 to: length.
	packetBuffer := packetBuffer copyFrom: length + 1 to: packetBuffer size.
	^SFTPMessage fromBytes: result requestId: requestId!

initialize
	"Initialize the receiver."

	super initialize.
	packetBuffer := ''.
	extensions := Dictionary new!

login: username password: password
	"Login the receiver with <username> and <password>."

	super login: username password: password.
	windowSizesClientToServer at: SSH_FXP_CHANNEL put: 16384.
	self 
		sendChannelOpen: SSH_FXP_CHANNEL;
		getChannelPacket: SSH_FXP_CHANNEL;
		sendChannelRequest: SSH_FXP_CHANNEL;
		getChannelPacket: SSH_FXP_CHANNEL;
		sendFTPInit!

processAttributes: response
	"Perform actions when dealing with an attributes request on <response>.
	 Answer attributes of false if error."

	response type = SSH_FXP_ATTRS 
		ifTrue: [^response attributes].
	response type = SSH_FXP_STATUS 
		ifTrue: [self logError: response status value: response message. ^false].
	self error: 'Expected SSH_FXP_ATTRS or SSH_FXP_STATUS'
	
!

processHandleRequest: response
	"Perform actions when dealing with a handle request on <response>.
	 Answer handle or nil if error."

	response type = SSH_FXP_HANDLE 
		ifTrue: [^response handle].
	response type = SSH_FXP_STATUS 
		ifTrue: [self logError: response status value: response message. ^nil].
	self error: 'Expected SSH_FXP_HANDLE or SSH_FXP_STATUS'

!

processName: response
	"Perform actions when dealing with single name request on <response>.
	 Answer name or '' if error."

	response type = SSH_FXP_NAME 
		ifTrue: [^response names first key].
	response type = SSH_FXP_STATUS 	
		ifTrue: [self logError: response status value: response message. ^''].
	self error: 'Expected SSH_FXP_NAME or SSH_FXP_STATUS'


!

processNextStatusRequestOk: response
	"Perform actions to check next status on <response> is ok.
	 Answer whether next status is ok."

	^response nextStatus = SSH_FXP_STATUS_OK 
		ifTrue: [true]
		ifFalse: [self logError: response status value: response message.	false]



!

processReadHandle: response
	"Perform actions when dealing with a data request on <response>.
	 Answer data from <response>."

	response type = SSH_FXP_DATA
		 ifTrue: [^response data].
	response type = SSH_FXP_STATUS 
		ifTrue: [self logError: response status value: response message. ^false]
		ifFalse: [self error: 'Expected SSH_FXP_DATA or SSH_FXP_STATUS']
!

processStatusRequestOk: response
	"Perform actions to check an ok status request on <response>.
	 Answer whether check operation is correct."

	response type = SSH_FXP_STATUS
		ifFalse: [self error: 'Expected SSH_FXP_NAME or SSH_FXP_STATUS'. ^false].
	response status = SSH_FXP_STATUS_OK 
		ifFalse: [self logError: response status value: response message. ^false].
	^true


!

putFile: fileName data: data
	"Upload a file to the server host named <fileName> with contents of <data>."

	| remoteFile handle |
	remoteFile := self realPath: fileName.
	remoteFile isNil ifTrue: [^false].
	self sendCreateFile: remoteFile.
	handle := self processHandleRequest: self getSFTP.
	^self sendData: data for: handle



	
	
!

pwd
	"Answer the actual pwd on the server host."

	^pwd!

readFile: handle size: size progress: aMonadicValuable
	"Read and answer <size> bytes of file pointed by <handle>.
	 Updates progress on <aMonadicValuable> while transfering."

	| data read response localFile |
	localFile := ReadWriteStream on: ''.
	read := 0.
	[read < size]	whileTrue: [
		self sendSFTP: (SFTPMessage messageReadHandle: handle read: read from: 0 windowSize: (2 raisedTo: 20)).
		response := self getSFTP.
		data := self processReadHandle: response.
		data isNil ifTrue: [^false].
		read := read + data size.
		localFile nextPutAll: data.
		aMonadicValuable value: (localFile contents size * 100 / size) asScaledDecimal integerPart asInteger].

	self sendSFTP: (SFTPMessage messageCloseHandle: handle).
	response := self getSFTP.
	self processStatusRequestOk: response.
	(self processNextStatusRequestOk: response) ifFalse: [^false].
	^localFile contents
	
!

readPutResponses: anInteger

	| i |
	i := anInteger.
	[i > 0] whileTrue: [
		self processStatusRequestOk: self getSFTP.
		i := i - 1 ].
	^true!

realPath: aString
	"This protocol represents file names as strings. File names are
   assumed to use the slash ('/') character as a directory separator.
   File names starting with a slash are 'absolute', and are relative to
   the root of the file system.  Names starting with any other character
   are relative to the user's default directory (home directory)."

	| file realPath length dir |
	file := ''.
	dir := aString.
	pwd notNil ifTrue: [
		aString last ~= $/ ifTrue: [
			file := self baseName: dir.
			dir := self dirName: dir].
		(dir = '.' or: [dir = pwd]) ifTrue: [^pwd, file].
		dir first ~= $/ ifTrue: [dir := pwd, '/', dir]].

	self sendSFTP: (SFTPMessage messageRealPath: dir).
	realPath := self processName: self getSFTP.
	^realPath, '/', file!

remoteFileSize: aString
	"Answer size in bytes of file refered by <aString>."

	^(self remoteFileStatus: aString) at: 'size'!

remoteFileStatus: aString
	"Answer attributes for file refered by <aString>."

	self sendSFTP: (SFTPMessage messageFileStat: aString).
	^self processAttributes: self getSFTP	!

sendChannelRead: aString
	"Send read data message for <aString> to server host."

	self sendSFTP: (SFTPMessage messageOpenRead: aString)!

sendChannelRequest: aNumber
	"Send request message for channel <aNumber> to server host."
 
	self send: (SSH2Message messageSFTPChannelRequest: (serverChannels at: aNumber)).
	channelStatus at: aNumber put: SSH_MSG_CHANNEL_REQUEST
!

sendClose: handle
	"Send close handle message for <handle> to server host."

	self sendSFTP: (SFTPMessage messageCloseHandle: handle)!

sendCreateFile: aString
	"Send create file <aString> message to server host."

	self sendSFTP: (SFTPMessage messageOpenWriteForced: aString)!

sendData: aString for: handle
	"Send binary data on <aString> to server host throught <handle>."

	| sent size i stream break temp data maxValue message |
	data := aString.
	size := data size.
	break := false.
	sent := 0.
	i := 0.
	
	[sent < size or: [break]] whileTrue: [
		maxValue := self sftpPacketSize min: data size.
		temp := data copyFrom: 1 to: maxValue.
		data := data copyFrom: maxValue + 1 to: data size.
		message := SFTPMessage messageWriteHandle: handle flag: 0 sentBytes: sent bytes: temp.
		self sendSFTP: message.
		sent := sent + message basicContents size.
		i := i + 1.	
		i = 50 ifTrue: [
			(self readPutResponses: i) ifFalse: [break := true].
			i := 0]].

	self readPutResponses: i.
	self sendSFTP: (SFTPMessage messageCloseHandle: handle).
	^self processStatusRequestOk: self getSFTP
!

sendFTPInit
	"Send SFTP init message to server host."

	| response |
	channelStatus at: SSH_FXP_CHANNEL put: SSH_MSG_CHANNEL_DATA.
	self sendSFTP: SFTPMessage messageSFTPInit.
	response := self getSFTP.
	self check: response type: SSH_FXP_VERSION errorMessage: 'Expected SSH_FXP_VERSION'.
	self verifyServerVersion: response.
	requestId := 1.
	pwd := self realPath: '.'
!

sendSFTP: aSFTPMessage
	"Send <aSFTPMessage> to server host."

	requestId notNil ifTrue: [aSFTPMessage requestId: requestId].
	^self sendToChannel: SSH_FXP_CHANNEL data: aSFTPMessage contents

	

	!

sendToChannel: aNumber data: aString
	"Send <aString> data to channel <aNumber>."

	[aString size > (packetSizesClientToServer at: aNumber)] 
		whileTrue: [
			windowSizesClientToServer 
				at: aNumber 
				put: (windowSizesClientToServer at: aNumber) - (packetSizesClientToServer at: aNumber).
			self checkWindowAdjust: self windowSize channel: aNumber.
			self send: (SSH2Message 
										messageChannel: (serverChannels at: aNumber) 
										data: (aString copyFrom: 1 to: (packetSizesClientToServer at: aNumber)))].

	windowSizesClientToServer at: aNumber put: (windowSizesClientToServer at: aNumber) - aString size.
	self checkWindowAdjust: self windowSize channel: aNumber.
	^self send: (SSH2Message messageChannel: (serverChannels at: aNumber) data: aString)

	
	
	
	!

sftpPacketSize
	"Answer the packet size parameter for sftp transfers."

	^4096!

verifyServerVersion: aSFTPMessage
	"Verify server version is compatible, signal an error if else."

	aSFTPMessage version = 3 ifFalse: [self error: 'Incompatible SFTP version'].
	version := aSFTPMessage version! !

SFTPClient initializeAfterLoad!


Object subclass: #SFTPMessage
    instanceVariableNames: 'type requestId '
    classVariableNames: ''
    poolDictionaries: 'SFTPConstants '!

!SFTPMessage class publicMethods !

associatedMessageTypes

	^#()!

fromBytes: aString requestId: requestId
	
	| type dataIndex |
	type := aString first value.
	dataIndex := requestId notNil ifTrue: [6] ifFalse: [2].
	^SFTPMessage fromType: type data: (aString copyFrom: dataIndex to: aString size)!

fromType: type data: aString

	^(self messageFor: type)
			buildFrom: aString;
			yourself!

messageClassFor: aNumber

	^self allSubclasses 
		detect: [:each | each associatedMessageTypes includes: aNumber]
		ifNone: [self]!

messageCloseHandle: handle

	^(self messageFor: SSH_FXP_CLOSE)
		data: handle;
		yourself!

messageFileStat: aString

	^(self messageFor: SSH_FXP_STAT)
		data: aString;
		yourself!

messageFor: aNumber

	^(self messageClassFor: aNumber) new
		type: aNumber;
		yourself!

messageOpenDir: aString 

	^(self messageFor: SSH_FXP_OPENDIR)
		data: aString;
		yourself!

messageOpenRead: aString 

	^(self messageFor: SSH_FXP_OPEN)
		file: aString;
		flags: SSH_FXP_OPEN_READ;
		attributes: 0;
		yourself
!

messageOpenWriteForced: aString 

	^(self messageFor: SSH_FXP_OPEN)
		file: aString;
		flags: ((SSH_FXP_OPEN_WRITE bitOr: SSH_FXP_OPEN_CREATE) bitOr: SSH_FXP_OPEN_TRUNCATE);
		attributes: 0;
		yourself!

messageReadHandle: handle read: bytes from: start windowSize: windowSize
		
	^(self messageFor: SSH_FXP_READ)
		handle: handle;
		start: start;
		read: bytes;
		windowSize: windowSize;
		yourself!

messageRealPath: aString 

	^(self messageFor: SSH_FXP_REALPATH)
		data: aString;
		yourself



!

messageSFTPInit

	^(self messageFor: SSH_FXP_INIT)
		data: 0 asCharacter asString, 0 asCharacter asString, 0 asCharacter asString, 3 asCharacter asString;
		yourself!

messageWriteHandle: handle flag: anInteger sentBytes: sentBytes bytes: aString
		
	^(self messageFor: SSH_FXP_WRITE)
		handle: handle;
		flag: anInteger;
		sent: sentBytes;
		bytes: aString;
		yourself! !

!SFTPMessage publicMethods !

basicContents

	^self binaryDescription inject: '' into: [:total :each | total, (each contentsFor: self)]!

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^OrderedCollection new!

buildFrom: aString
	"Build the receiver from <aString>."

	| stream |
	stream := ReadStream on: aString.
	self binaryDescription do: [:each | each build: self from: stream]!

byteFromBinary: aString

	| value |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		each = $1 ifTrue: [value := value + (2 raisedTo: index - 1)]].
	^value asCharacter!

contents 
	"Answer a Collection with binary contents of the receiver."	

	^self describeString: type asCharacter asString, self requestIdDescription, self basicContents



!

describeString: aString
	"Answer a binary representation for <aString>."

	^(self integerToString: aString size), aString


!

integerToString: anInteger
	"Answer a string representing <anInteger> in little endian format, padded to 32 bits."

	^self integerToString: anInteger bits: 32!

integerToString: anInteger bits: aNumber
	"Answer a string representing <anInteger> in little endian format, padded to <aNumber> bits."

	| stream index binary |
	binary := ''.
	stream := ReadWriteStream on: ''.
	index := 0.

	(anInteger printStringRadix: 2 padTo: aNumber) reverse do: [:each | 
		index := index + 1.
		binary := binary, each asString.
		index = 8 ifTrue: [
			index := 0. 
			stream nextPut: (self byteFromBinary: binary reverse).
			binary := '' ]].

	index > 0 ifTrue: [
		1 to: 8 - index do: [:each | binary := $0 asString, binary].
		stream nextPut: (self byteFromBinary: binary)].
	
	^stream contents reverse
	!

requestId

	^requestId!

requestId: anObject

	requestId := anObject!

requestIdDescription

	^requestId isNil
		ifTrue: [''] 
		ifFalse: [self integerToString: requestId]!

type

	^type!

type: anObject

	type := anObject! !

SFTPMessage initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageAttributes
    instanceVariableNames: 'attributes '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageAttributes class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_ATTRS
! !

!SFTPMessageAttributes publicMethods !

attributes

	 ^attributes!

buildFrom: aString
	"Build the receiver from <aString>."

	super buildFrom: aString.
	self parseAttributes: aString!

parseAttributes: aString
	"Parse attributes from <aString> and place them into attributes instance variable."

	| flags value upper size |
	value := aString.
	flags := value sshLongAt: 1.
	value := value copyFrom: 5 to: value size.
	attributes := Dictionary new.

	(flags bitAnd: SSH_FXP_ATTR_SIZE) ~= 0 ifTrue: [
		upper := value sshLongAt: 1. 
		size := value sshLongAt: 2. 
		attributes at: 'size' put: 
			(upper ~= 0
				ifTrue: [(2 raisedTo: 32) - 1]
				ifFalse: [size < 0 ifTrue: [(size bitAnd: 2147483647) + 134217728] ifFalse: [size]])]! !

SFTPMessageAttributes initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageData
    instanceVariableNames: 'data '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageData class publicMethods !

associatedMessageTypes

	^OrderedCollection new 
		add: SSH_FXP_DATA;
		add: SSH_FXP_INIT;
		add: SSH_FXP_REALPATH;
		add: SSH_FXP_OPENDIR;
		add: SSH_FXP_CLOSE;
		add: SSH_FXP_STAT;
		yourself! !

!SFTPMessageData publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #data))!

data

	^data!

data: anObject

	data := anObject! !

SFTPMessageData initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageHandle
    instanceVariableNames: 'handle '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageHandle class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_HANDLE
! !

!SFTPMessageHandle publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #handle))
!

handle

	 ^handle!

handle: anObject

	handle := anObject! !

SFTPMessageHandle initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageName
    instanceVariableNames: 'id names fileName attributes '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageName class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_NAME
! !

!SFTPMessageName publicMethods !

attributes

	^attributes!

attributes: anObject

	attributes := anObject!

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #id)
			with: (SSHMessageFieldString for: #fileName)
			with: (SSHMessageFieldString for: #attributes))
!

fileName

	^fileName!

fileName: anObject

	fileName := anObject!

id

	^id!

id: anObject

	id := anObject!

names

	^OrderedCollection with: fileName -> attributes! !

SFTPMessageName initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageOpen
    instanceVariableNames: 'file flags attributes '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageOpen class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_OPEN! !

!SFTPMessageOpen publicMethods !

attributes

	^attributes
!

attributes: anObject

	attributes := anObject
!

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #file)
			with: (SSHMessageFieldInteger for: #flags)
			with: (SSHMessageFieldInteger for: #attributes))

!

file

	^file
!

file: anObject

	file := anObject
!

flags

	^flags
!

flags: anObject

	flags := anObject
! !

SFTPMessageOpen initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageRead
    instanceVariableNames: 'handle read start windowSize '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageRead class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_READ! !

!SFTPMessageRead publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #handle)
			with: (SSHMessageFieldInteger for: #start)
			with: (SSHMessageFieldInteger for: #read)
			with: (SSHMessageFieldInteger for: #windowSize))


!

handle

	^handle!

handle: anObject

	handle := anObject!

read

	^read!

read: anObject

	read := anObject!

start

	^start!

start: anObject

	start := anObject!

windowSize

	^windowSize!

windowSize: anObject

	windowSize := anObject! !

SFTPMessageRead initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageStatus
    instanceVariableNames: 'status message rawData '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageStatus class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_STATUS! !

!SFTPMessageStatus publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #status)
			with: (SSHMessageFieldString for: #message))




	!

buildFrom: aString
	"Build the receiver from <aString>."

	super buildFrom: aString.
	rawData := aString
	!

message
	
	^message!

message: anObject
	
	message := anObject!

nextStatus
	
	| str length |
	length := rawData sshLongAt: 2.
	str := rawData copyFrom: 9 + length to: rawData size.
	^str sshLongAt: 1
!

status
	^status!

status: anObject
	
	status := anObject! !

SFTPMessageStatus initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageVersion
    instanceVariableNames: 'version '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageVersion class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_VERSION! !

!SFTPMessageVersion publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #version))
!

version
	
	^version!

version: anObject
	
	version := anObject! !

SFTPMessageVersion initializeAfterLoad!


SFTPMessage subclass: #SFTPMessageWrite
    instanceVariableNames: 'handle sent bytes flag '
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPMessageWrite class publicMethods !

associatedMessageTypes

	^Array 
			with: SSH_FXP_WRITE! !

!SFTPMessageWrite publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection 
			with: (SSHMessageFieldString for: #handle)
			with: (SSHMessageFieldInteger for: #flag)
			with: (SSHMessageFieldInteger for: #sent)
			with: (SSHMessageFieldString for: #bytes))


!

bytes
	^bytes!

bytes: anObject
	
	bytes := anObject!

flag
	^flag!

flag: anObject

	flag := anObject!

handle
	^handle!

handle: anObject

	handle := anObject!

sent
	^sent!

sent: anObject

	sent := anObject! !

SFTPMessageWrite initializeAfterLoad!



Object subclass: #SSH2Message
    instanceVariableNames: 'type '
    classVariableNames: ''
    poolDictionaries: 'SSH2Constants '!

!SSH2Message class publicMethods !

associatedMessageTypes

	^#()!

fromBytes: aString

	^(self messageFor: aString first value)
			buildFrom: aString;
			yourself!

messageAuthorizationRequestUser: username password: password
	"Answer a new SSH_MSG_USERAUTH_REQUEST username/password message authorization with <username> and <password>."
	
	^(SSH2Message messageFor: SSH_MSG_USERAUTH_REQUEST)
		user: username;
		service: 'ssh-connection'; 
		method: 'password';
		wantReply: false;
		password: password;
		yourself!

messageChannel: anInteger data: aString
	"Answer a new SSH_MSG_CHANNEL_DATA message for channel <anInteger>."
	
	^(SSH2Message messageFor: SSH_MSG_CHANNEL_DATA)
		channel: anInteger;
		data: aString;
		yourself!

messageChannelRequest: aNumber command: aString
	"Answer a new SSH_MSG_CHANNEL_REQUEST message for channel <anInteger>."
	
	^(SSH2MessageChannelRequest messageFor: SSH_MSG_CHANNEL_REQUEST)
		channel: aNumber;
		requestType: 'exec';
		wantReply: true;
		commandDescription: aString;
		yourself!

messageClassFor: aNumber

	^self allSubclasses 
		detect: [:each | each associatedMessageTypes includes: aNumber]
		ifNone: [self]!

messageCloseChannel: anInteger
	"Answer a new SSH_MSG_CHANNEL_CLOSE message for channel <anInteger>."
	
	^(SSH2MessageChannel messageFor: SSH_MSG_CHANNEL_CLOSE)
		channel: anInteger;
		yourself!

messageDisconnectReason: anInteger
	"Answer a new SSH_MSG_DISCONNECT message for reason <anInteger>."
	
	^(SSH2Message messageFor: SSH_MSG_DISCONNECT)
		reason: anInteger;
		description: '';
		languajeTag: '';
		yourself
!

messageFor: aNumber

	^(self messageClassFor: aNumber) new
		type: aNumber;
		yourself!

messageKexInitCookie: cookieString 
keyExchangeAlgorithms: keyExchangeAlgorithms
serverHostKeyAlgorithms: serverHostAlgorithms
encryptionClientToServerAlgorithms: encryptionAlgorithmsClient
encryptionServerToClientAlgorithms: encryptionAlgorithmsServer
macAlgorithmsClientToServer: macAlgorithmsServer
macAlgorithmsServerToClient: macAlgorithmsClient
compressionAlgorithmsClientToServer: compressionAlgorithmsClient
compressionAlgorithmsServerToClient: compressionAlgorithmsServer
languajesClientToServer: languajesClient
languajesServerToClient: languajesServer	

	^(SSH2Message messageFor: SSH_MSG_KEXINIT)
		cookie: cookieString;
		keyExchangeAlgorithms: keyExchangeAlgorithms;
		serverHostKeyAlgorithms: serverHostAlgorithms;
		encryptionAlgorithmsClientToServer: encryptionAlgorithmsClient;
		encryptionAlgorithmsServerToClient: encryptionAlgorithmsServer;
		macAlgorithmsClientToServer: macAlgorithmsServer;
		macAlgorithmsServerToClient: macAlgorithmsClient;
		compressionAlgorithmsClientToServer: compressionAlgorithmsClient;
		compressionAlgorithmsServerToClient: compressionAlgorithmsServer;
		languajesClientToServer: languajesClient;
		languajesServerToClient: languajesServer;
		yourself
!

messageKeyExchangeDHInit: aString
	"Answer a new SSH_MSG_KEXDH_INIT message for key <aString>."
	
	^(SSH2MessageData messageFor: SSH_MSG_KEXDH_INIT)
		data: aString;
		yourself!

messageNewKeys
	"Answer a new SSH_MSG_NEWKEYS message."
	
	^SSH2Message messageFor: SSH_MSG_NEWKEYS
!

messageOpenChannelSession: anInteger windowSize: windowSize packetSize: packetSize
	"Answer a new SSH_MSG_CHANNEL_OPEN message for channel <anInteger> in mode 'session'."
	
	^(SSH2Message messageFor: SSH_MSG_CHANNEL_OPEN)
		channel: anInteger;
		sessionType: 'session';
		windowSize: windowSize;
		packetSize: packetSize;
		yourself!

messageSFTPChannelRequest: aNumber
	"Answer a new SSH_MSG_CHANNEL_REQUEST message for channel <anInteger>."
	
	^(SSH2Message messageFor: SSH_MSG_CHANNEL_REQUEST)
		channel: aNumber;
		requestType: 'subsystem';
		wantReply: true;
		commandDescription: 'sftp';
		yourself!

messageSSHLoginRequest
	"Answer a new SSH_MSG_SERVICE_REQUEST message for reason <anInteger>."
	
	^(SSH2MessageData messageFor: SSH_MSG_SERVICE_REQUEST)
		data: 'ssh-userauth';
		yourself

!

messageWindowAdjust: channel size: size
	"Answer a new SSH_MSG_CHANNEL_CLOSE message for channel <anInteger>."
	
	^(SSH2Message messageFor: SSH_MSG_CHANNEL_WINDOW_ADJUST)
		channel: channel;
		size: size;
		yourself! !

!SSH2Message publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^OrderedCollection with: (SSHMessageFieldByte for: #type)!

buildFrom: aString
	"Build the receiver from <aString>."

	| stream |
	stream := ReadStream on: aString.
	self binaryDescription do: [:each | each build: self from: stream]

!

contents 
	"Answer a Collection with binary contents of the receiver."	

	^self binaryDescription 
		inject: '' 
		into: [:total :each | total, (each contentsFor: self)]!

type

	^type!

type: aNumber

	type := aNumber! !

SSH2Message initializeAfterLoad!


SSH2Message subclass: #SSH2MessageAuthorizationRequest
    instanceVariableNames: 'user service method wantReply specific '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageAuthorizationRequest class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_USERAUTH_REQUEST
! !

!SSH2MessageAuthorizationRequest publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection new
			add: (SSHMessageFieldString for: #user);
			add: (SSHMessageFieldString for: #service);
			add: (SSHMessageFieldString for: #method);
			add: (SSHMessageFieldHole for: 0 asCharacter asString);
			add: (SSHMessageFieldString for: #specific);
			yourself)!

method
	
	^method!

method: anObject
	
	method := anObject!

password: anObject
	"Set specific data for password on the receiver to <anObject>."

	self specific: anObject!

service
	
	^service!

service: anObject
	
	service := anObject!

specific
	
	^specific!

specific: anObject
	
	specific := anObject!

user
	
	^user!

user: anObject
	
	user := anObject!

wantReply
	
	^wantReply!

wantReply: anObject
	
	wantReply := anObject! !

SSH2MessageAuthorizationRequest initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannel
    instanceVariableNames: 'channel '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannel class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_CLOSE
! !

!SSH2MessageChannel publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel))!

channel

	^channel!

channel: anObject

	channel := anObject! !

SSH2MessageChannel initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannelData
    instanceVariableNames: 'channel data '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannelData class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_DATA
! !

!SSH2MessageChannelData publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldString for: #data))!

channel

	^channel!

channel: anObject

	channel := anObject!

data

	^data!

data: anObject

	data := anObject! !

SSH2MessageChannelData initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannelExtendedData
    instanceVariableNames: 'channel dataType data '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannelExtendedData class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_EXTENDED_DATA
! !

!SSH2MessageChannelExtendedData publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldInteger for: #dataType)
			with: (SSHMessageFieldString for: #data))
!

channel

	^channel!

channel: anObject

	channel := anObject!

data

	^data!

data: anObject

	data := anObject!

dataType

	^dataType!

dataType: anObject

	dataType := anObject! !

SSH2MessageChannelExtendedData initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannelOpen
    instanceVariableNames: 'channel sessionType windowSize packetSize specific '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannelOpen class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_OPEN
! !

!SSH2MessageChannelOpen publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #sessionType)
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldInteger for: #windowSize)
			with: (SSHMessageFieldInteger for: #packetSize))!

channel

	^channel!

channel: anObject

	channel := anObject!

packetSize

	^packetSize!

packetSize: anObject

	packetSize := anObject!

sessionType

	^sessionType!

sessionType: anObject

	sessionType := anObject!

specific

	^specific!

specific: anObject

	specific := anObject!

windowSize

	^windowSize!

windowSize: anObject

	windowSize := anObject! !

SSH2MessageChannelOpen initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannelOpenConfirmation
    instanceVariableNames: 'channel serverChannel packetSize '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannelOpenConfirmation class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_OPEN_CONFIRMATION
! !

!SSH2MessageChannelOpenConfirmation publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldInteger for: #serverChannel)
			with: (SSHMessageFieldHole for: '    ')
			with: (SSHMessageFieldInteger for: #packetSize))!

channel

	^channel
!

channel: anObject
	
	channel := anObject
!

packetSize

	^packetSize
!

packetSize: anObject

	packetSize := anObject
!

serverChannel

	^serverChannel
!

serverChannel: anObject

	serverChannel := anObject

! !

SSH2MessageChannelOpenConfirmation initializeAfterLoad!


SSH2Message subclass: #SSH2MessageChannelRequest
    instanceVariableNames: 'channel requestType wantReply specific '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageChannelRequest class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_REQUEST! !

!SSH2MessageChannelRequest publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldString for: #requestType)
			with: (SSHMessageFieldBoolean for: #wantReply)
			with: (SSHMessageFieldString for: #specific))

!

channel 

	^channel
!

channel: anObject

	channel := anObject
!

commandDescription: aString
	"Set specific data for a command description on the receiver to <aString>."

	self specific: aString!

requestType 

	^requestType

!

requestType: anObject

	requestType := anObject
!

specific

	^specific
!

specific: anObject

	specific := anObject
!

wantReply 

	^wantReply

!

wantReply: anObject

	wantReply := anObject

! !

SSH2MessageChannelRequest initializeAfterLoad!


SSH2Message subclass: #SSH2MessageData
    instanceVariableNames: 'data '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageData class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_KEXDH_INIT
		with: SSH_MSG_SERVICE_REQUEST
! !

!SSH2MessageData publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #data))
!

data

	^data!

data: anObject

	data := anObject! !

SSH2MessageData initializeAfterLoad!


SSH2Message subclass: #SSH2MessageDisconnect
    instanceVariableNames: 'reason description languajeTag '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageDisconnect class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_DISCONNECT! !

!SSH2MessageDisconnect publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldString for: #description)
			with: (SSHMessageFieldString for: #reason)
			with: (SSHMessageFieldString for: #languajeTag))
!

description

	^description
!

description: anObject

	description := anObject
!

languajeTag

	^languajeTag
!

languajeTag: anObject

	languajeTag := anObject
!

reason

	^reason
!

reason: anObject

	reason := anObject
! !

SSH2MessageDisconnect initializeAfterLoad!


SSH2Message subclass: #SSH2MessageKexDHReply
    instanceVariableNames: 'serverKey serverPublicKeyData f hashSignature publicKeyFormat '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageKexDHReply class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_KEXDH_REPLY
! !

!SSH2MessageKexDHReply publicMethods !

buildFrom: aString
	"Build the receiver from <aString>."

	| value bytes publicKeyData signatureData signatureFormat length |	
	super buildFrom: aString.
	value := aString copyFrom: 2 to: aString size.
	length := value sshLongAt: 1.
	value := value copyFrom: 5 to: value size.
	serverPublicKeyData := value copyFrom: 1 to: length.
	publicKeyData := serverPublicKeyData.
	value := value copyFrom: length + 1 to: value size.

	length := publicKeyData sshLongAt: 1.
	publicKeyData := publicKeyData copyFrom: 5 to: publicKeyData size.
	publicKeyFormat := publicKeyData copyFrom: 1 to: length.

	length := value sshLongAt: 1.
	value := value copyFrom: 5 to: value size.
	serverKey := value copyFrom: 1 to: length.
	value := value copyFrom: length + 1 to: value size.

	length := value sshLongAt: 1.
	value := value copyFrom: 5 to: value size.	
	signatureData := value copyFrom: 1 to: length.
	value := value copyFrom: length + 1 to: value size.

	length := signatureData sshLongAt: 1.
	signatureData := signatureData copyFrom: 5 to: signatureData size.
	signatureFormat := signatureData copyFrom: 1 to: length. 
	signatureData := signatureData copyFrom: length + 1 to: signatureData size

	!

f

	^f!

f: anObject

	f := anObject!

hashSignature

	^hashSignature!

hashSignature: anObject

	hashSignature := anObject!

publicKeyFormat

	^publicKeyFormat!

publicKeyFormat: anObject

	publicKeyFormat := anObject!

serverKey

	^serverKey!

serverKey: anObject

	serverKey := anObject!

serverPublicKeyData

	^serverPublicKeyData! !

SSH2MessageKexDHReply initializeAfterLoad!


SSH2Message subclass: #SSH2MessageKexInit
    instanceVariableNames: 'cookie keyExchangeAlgorithms serverHostKeyAlgorithms encryptionAlgorithmsClientToServer encryptionAlgorithmsServerToClient macAlgorithmsClientToServer macAlgorithmsServerToClient compressionAlgorithmsClientToServer compressionAlgorithmsServerToClient languajesClientToServer languajesServerToClient firstKexPacketFollows reserved payload '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageKexInit class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_KEXINIT
! !

!SSH2MessageKexInit publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection new
			add: (SSHMessageFieldFixedString for: #cookie size: 16);
			add: (SSHMessageFieldStringCollection for: #keyExchangeAlgorithms);
			add: (SSHMessageFieldStringCollection for: #serverHostKeyAlgorithms);
			add: (SSHMessageFieldStringCollection for: #encryptionAlgorithmsClientToServer);
			add: (SSHMessageFieldStringCollection for: #encryptionAlgorithmsServerToClient);
			add: (SSHMessageFieldStringCollection for: #macAlgorithmsClientToServer);
			add: (SSHMessageFieldStringCollection for: #macAlgorithmsServerToClient);
			add: (SSHMessageFieldStringCollection for: #compressionAlgorithmsClientToServer);
			add: (SSHMessageFieldStringCollection for: #compressionAlgorithmsServerToClient);
			add: (SSHMessageFieldStringCollection for: #languajesClientToServer);
			add: (SSHMessageFieldStringCollection for: #languajesServerToClient);
			add: (SSHMessageFieldHole for: (String withAll: (#(0 0 0 0 0) collect: [:each | each asCharacter])));
			yourself)
!

buildFrom: aString
	"Build the receiver from <aString>."

	payload := aString.
	super buildFrom: aString

!

compressionAlgorithmsClientToServer

	^compressionAlgorithmsClientToServer!

compressionAlgorithmsClientToServer: anObject

	compressionAlgorithmsClientToServer := anObject!

compressionAlgorithmsServerToClient

	^compressionAlgorithmsServerToClient!

compressionAlgorithmsServerToClient: anObject

	compressionAlgorithmsServerToClient := anObject!

cookie

	^cookie!

cookie: anObject

	^cookie := anObject
!

encryptionAlgorithmsClientToServer

	^encryptionAlgorithmsClientToServer!

encryptionAlgorithmsClientToServer: anObject

	encryptionAlgorithmsClientToServer := anObject!

encryptionAlgorithmsServerToClient

	^encryptionAlgorithmsServerToClient!

encryptionAlgorithmsServerToClient: anObject

	encryptionAlgorithmsServerToClient := anObject
!

firstKexPacketFollows   

	^firstKexPacketFollows   !

keyExchangeAlgorithms

	^keyExchangeAlgorithms!

keyExchangeAlgorithms: anObject

	keyExchangeAlgorithms := anObject!

languajesClientToServer 

	^languajesClientToServer !

languajesClientToServer: anObject

	languajesClientToServer := anObject!

languajesServerToClient  

	^languajesServerToClient  !

languajesServerToClient: anObject

	languajesServerToClient := anObject!

macAlgorithmsClientToServer

	^macAlgorithmsClientToServer!

macAlgorithmsClientToServer: anObject

	macAlgorithmsClientToServer := anObject!

macAlgorithmsServerToClient

	^macAlgorithmsServerToClient!

macAlgorithmsServerToClient: anObject

	macAlgorithmsServerToClient := anObject!

payload

	^payload!

serverHostKeyAlgorithms

	^serverHostKeyAlgorithms!

serverHostKeyAlgorithms: anObject

	serverHostKeyAlgorithms := anObject! !

SSH2MessageKexInit initializeAfterLoad!


SSH2Message subclass: #SSH2MessageWindowAdjust
    instanceVariableNames: 'channel size '
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageWindowAdjust class publicMethods !

associatedMessageTypes

	^Array 
		with: SSH_MSG_CHANNEL_WINDOW_ADJUST
! !

!SSH2MessageWindowAdjust publicMethods !

binaryDescription
	"Answer a Collection of fields which describes the binary contents of the receiver."

	^super binaryDescription, 
		(OrderedCollection
			with: (SSHMessageFieldInteger for: #channel)
			with: (SSHMessageFieldInteger for: #size))
!

channel

	^channel!

channel: anObject

	channel := anObject!

size

	^size!

size: anObject

	size := anObject! !

SSH2MessageWindowAdjust initializeAfterLoad!


Object subclass: #SSHHostConfiguration
    instanceVariableNames: 'identifier publicKey publicKeyFormat publicKeyData privateKey cookie kexInitPayload keyExchangeAlgorithms serverHostKeysAlgorithms encryptionClientToServerAlgorithms encryptionServerToClientAlgorithms macClientToServerAlgorithms macServerToClientAlgorithms compressionClientToServerAlgorithms compressionServerToClientAlgorithms languajesClientToServer languajesServerToClient '
    classVariableNames: ''
    poolDictionaries: ''!

!SSHHostConfiguration class publicMethods !

defaultIdentified: aString cookie: anotherString

	^self new
		identifier: aString;
		cookie: anotherString;
		keyExchangeAlgorithms: self possibleKeyExchangeAlgorithms;
		serverHostKeysAlgorithms: self possibleServerHostKeyAlgorithms;
		encryptionClientToServerAlgorithms: self possibleEncryptionAlgorithms;
		encryptionServerToClientAlgorithms: self possibleEncryptionAlgorithms;
		macClientToServerAlgorithms: self possibleMacAlgorithms;
		macServerToClientAlgorithms: self possibleMacAlgorithms;
		compressionClientToServerAlgorithms: self possibleCompressionAlgorithms;
		compressionServerToClientAlgorithms: self possibleCompressionAlgorithms;
		languajesClientToServer: '';
		languajesServerToClient: '';
		yourself!

possibleCompressionAlgorithms
	"Answer a collection with possible compression algorithms descriptions."

	^(CompressionAlgorithm allSubclasses 
		reject: [:each | each isAbstract])
			collect: [:each | each description]
!

possibleEncryptionAlgorithms 
	"Answer a collection with possible encryption algorithms descriptions."

	^(EncryptionAlgorithm allSubclasses 
		reject: [:each | each isAbstract])
			collect: [:each | each description]!

possibleKeyExchangeAlgorithms
	"Answer a collection with possible key exchange algorithms descriptions."

	^(DiffieHellman allSubclasses 
		reject: [:each | each isAbstract])
			collect: [:each | each description]!

possibleMacAlgorithms
	"Answer a collection with possible MAC algorithms descriptions."

	^(HMACAlgorithm allSubclasses 
		reject: [:each | each isAbstract])
			collect: [:each | each description]!

possibleServerHostKeyAlgorithms
	"Answer a collection with possible server host key algorithms descriptions."

	^OrderedCollection
		with: 'ssh-rsa'
		with: 'ssh-dss'! !

!SSHHostConfiguration publicMethods !

checkServerHostKeyAlgorithms: aSSHHostConfiguration

	| algorithms |
	algorithms := serverHostKeysAlgorithms intersection: aSSHHostConfiguration serverHostKeysAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible server host key algorithms found'].
	publicKeyFormat = algorithms first ifFalse: [self error: 'Sever host key algorithm mismatch']!

compatibleCompressionAlgorithm: aSSHHostConfiguration

	| algorithms |
	algorithms := compressionClientToServerAlgorithms intersection: aSSHHostConfiguration compressionClientToServerAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible compression algorithms found'].
	^CompressionAlgorithm fromDescription: algorithms first

!

compatibleDecompressionAlgorithm: aSSHHostConfiguration

	| algorithms |
	algorithms := compressionServerToClientAlgorithms intersection: aSSHHostConfiguration compressionServerToClientAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible compression algorithms found'].
	^CompressionAlgorithm fromDescription: algorithms first

!

compatibleDecryptionAlgorithm: aSSHHostConfiguration 
	"Answer a compatible decryption algorithm for the receiver and <aSSHHostConfiguration>."

	| algorithms |
	algorithms := encryptionServerToClientAlgorithms intersection: aSSHHostConfiguration encryptionServerToClientAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible client to server encryption algorithm found'].
	^EncryptionAlgorithm fromDescription: algorithms first
!

compatibleEncryptionAlgorithm: aSSHHostConfiguration 
	"Answer a compatible decryption algorithm for the receiver and <aSSHHostConfiguration>."

	| algorithms |
	algorithms := encryptionClientToServerAlgorithms intersection: aSSHHostConfiguration encryptionClientToServerAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible client to server encryption algorithm found'].
	^EncryptionAlgorithm fromDescription: algorithms first

!

compatibleHMACCheckAlgorithm: aSSHHostConfiguration

	| algorithms |
	algorithms := macServerToClientAlgorithms intersection: aSSHHostConfiguration macServerToClientAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible HMAC server to client found'].
	^HMACAlgorithm fromDescription: algorithms first
!

compatibleHMACCreateAlgorithm: aSSHHostConfiguration

	| algorithms |
	algorithms := macClientToServerAlgorithms intersection: aSSHHostConfiguration macClientToServerAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible HMAC client to server found'].
	^HMACAlgorithm fromDescription: algorithms first!

compatibleKeyExchangeAlgorithm: aSSHHostConfiguration 
	"Answer a compatible key exchange algorithm for the receiver and <aSSHHostConfiguration>."

	| algorithms |
	algorithms := keyExchangeAlgorithms intersection: aSSHHostConfiguration keyExchangeAlgorithms.
	algorithms isEmpty ifTrue: [self error: 'No compatible key exchange algorithm found'].
	^DiffieHellman fromDescription: algorithms first
!

compressionClientToServerAlgorithms

	^compressionClientToServerAlgorithms!

compressionClientToServerAlgorithms: anObject

	compressionClientToServerAlgorithms := anObject!

compressionServerToClientAlgorithms

	^compressionServerToClientAlgorithms!

compressionServerToClientAlgorithms: anObject

	compressionServerToClientAlgorithms := anObject!

configureFromDHReply: aSSH2Message

	publicKey := aSSH2Message serverKey.
	publicKeyFormat := aSSH2Message publicKeyFormat.
	publicKeyData := aSSH2Message serverPublicKeyData!

configureFromKeyExchangeInit: aSSH2Message

	kexInitPayload := aSSH2Message payload.
	keyExchangeAlgorithms := aSSH2Message keyExchangeAlgorithms.
	serverHostKeysAlgorithms := aSSH2Message serverHostKeyAlgorithms.
	encryptionClientToServerAlgorithms := aSSH2Message encryptionAlgorithmsClientToServer.
	encryptionServerToClientAlgorithms := aSSH2Message encryptionAlgorithmsServerToClient.
	macClientToServerAlgorithms := aSSH2Message macAlgorithmsClientToServer.
	macServerToClientAlgorithms := aSSH2Message macAlgorithmsServerToClient.
	compressionClientToServerAlgorithms := aSSH2Message compressionAlgorithmsClientToServer.
	compressionServerToClientAlgorithms := aSSH2Message compressionAlgorithmsServerToClient.
	languajesClientToServer := aSSH2Message languajesClientToServer.
	languajesServerToClient := aSSH2Message languajesServerToClient!

cookie

	^cookie!

cookie: anObject

	cookie := anObject!

encryptionClientToServerAlgorithms

	^encryptionClientToServerAlgorithms!

encryptionClientToServerAlgorithms: anObject

	encryptionClientToServerAlgorithms := anObject!

encryptionServerToClientAlgorithms

	^encryptionServerToClientAlgorithms!

encryptionServerToClientAlgorithms: anObject

	encryptionServerToClientAlgorithms := anObject!

identifier

	^identifier!

identifier: anObject

	identifier := anObject!

kexInitPayload

	^kexInitPayload!

keyExchangeAlgorithms

	^keyExchangeAlgorithms!

keyExchangeAlgorithms: anObject

	keyExchangeAlgorithms := anObject!

languajesClientToServer

	^languajesClientToServer!

languajesClientToServer: anObject

	languajesClientToServer := anObject!

languajesServerToClient

	^languajesServerToClient!

languajesServerToClient: anObject

	languajesServerToClient := anObject!

macClientToServerAlgorithms

	^macClientToServerAlgorithms!

macClientToServerAlgorithms: anObject

	macClientToServerAlgorithms := anObject!

macServerToClientAlgorithms

	^macServerToClientAlgorithms!

macServerToClientAlgorithms: anObject

	macServerToClientAlgorithms := anObject!

messageForKeyExchange

	| message |
	message := SSH2Message 
							messageKexInitCookie: cookie
							keyExchangeAlgorithms: keyExchangeAlgorithms
							serverHostKeyAlgorithms: serverHostKeysAlgorithms
							encryptionClientToServerAlgorithms: encryptionClientToServerAlgorithms
							encryptionServerToClientAlgorithms: encryptionServerToClientAlgorithms
							macAlgorithmsClientToServer: macClientToServerAlgorithms
							macAlgorithmsServerToClient: macServerToClientAlgorithms
							compressionAlgorithmsClientToServer: compressionClientToServerAlgorithms
							compressionAlgorithmsServerToClient: compressionServerToClientAlgorithms
							languajesClientToServer: languajesClientToServer
							languajesServerToClient: languajesServerToClient.
	kexInitPayload := message contents.
	^message!

privateKey

	^privateKey!

privateKey: anObject

	privateKey := anObject!

publicKey

	^publicKey!

publicKey: anObject

	publicKey := anObject!

publicKeyData

	^publicKeyData!

serverHostKeysAlgorithms

	^serverHostKeysAlgorithms!

serverHostKeysAlgorithms: anObject

	serverHostKeysAlgorithms := anObject! !

SSHHostConfiguration initializeAfterLoad!


Object subclass: #SSHMessageField
    instanceVariableNames: 'selector '
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageField class publicMethods !

for: aSymbol

	^self new
		selector: aSymbol;
		yourself! !

!SSHMessageField publicMethods !

build: anObject from: aStream

	anObject 
		perform: self setterSelector 
		with: (self fromBinary: aStream)!

byteFromBinary: aString

	| value |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		each = $1 ifTrue: [value := value + (2 raisedTo: index - 1)]].
	^value asCharacter!

contentsFor: anObject
	"Answer binary contents of the receiver on <anObject>."

	| value |
	value := anObject perform: self selector.
	^self toBinary: value!

describeString: aString
	"Answer a binary representation for <aString>."

	^(self integerToString: aString size), aString


!

integerToString: anInteger
	"Answer a string representing <anInteger> in little endian format, padded to 32 bits."

	^self integerToString: anInteger bits: 32!

integerToString: anInteger bits: aNumber
	"Answer a string representing <anInteger> in little endian format, padded to <aNumber> bits."

	| stream index binary |
	binary := ''.
	stream := ReadWriteStream on: ''.
	index := 0.

	(anInteger printStringRadix: 2 padTo: aNumber) reverse do: [:each | 
		index := index + 1.
		binary := binary, each asString.
		index = 8 ifTrue: [
			index := 0. 
			stream nextPut: (self byteFromBinary: binary reverse).
			binary := '' ]].

	index > 0 ifTrue: [
		1 to: 8 - index do: [:each | binary := $0 asString, binary].
		stream nextPut: (self byteFromBinary: binary)].
	
	^stream contents reverse
	!

selector

	^selector!

selector: anObject

	selector := anObject!

setterSelector
	"Answer the setter selector for the receiver."

	^(self selector asString, ':') asSymbol
! !

SSHMessageField initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldBoolean
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldBoolean publicMethods !

fromBinary: aStream
	
	 ^aStream next value = 1
!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."

	 ^(anObject ifTrue: [1] ifFalse: [0]) 
			asCharacter asString
! !

SSHMessageFieldBoolean initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldByte
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldByte publicMethods !

fromBinary: aStream
	
	 ^aStream next value!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."

	^anObject asCharacter asString
! !

SSHMessageFieldByte initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldFixedString
    instanceVariableNames: 'size '
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldFixedString class publicMethods !

for: aSymbol size: anInteger

	^self new
		selector: aSymbol;
	 	size: anInteger;
		yourself! !

!SSHMessageFieldFixedString publicMethods !

fromBinary: aStream
	
	 ^aStream next: size
!

size

	^size!

size: anObject

	size := anObject!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."
	
	^anObject! !

SSHMessageFieldFixedString initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldHole
    instanceVariableNames: 'contents '
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldHole class publicMethods !

for: aString

	^self new
		contents: aString;
		yourself! !

!SSHMessageFieldHole publicMethods !

build: anObject from: aStream
	
	aStream next: contents size!

contents

	^contents!

contents: anObject

	contents := anObject!

contentsFor: anObject

	^contents! !

SSHMessageFieldHole initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldInteger
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldInteger publicMethods !

fromBinary: aStream
	
	 ^(aStream next: 4) sshLong!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."

	^self integerToString: anObject! !

SSHMessageFieldInteger initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldString
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldString publicMethods !

fromBinary: aStream
	
	| length |
	length := (aStream next: 4) sshLong.
	^aStream next: length!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."
	
	^self describeString: anObject! !

SSHMessageFieldString initializeAfterLoad!


SSHMessageField subclass: #SSHMessageFieldStringCollection
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHMessageFieldStringCollection publicMethods !

describeCollection: aCollection

	| stream |
	stream := ReadWriteStream on: ''.
	aCollection 
		do: [:each | stream nextPutAll: each]	
		separatedBy: [stream nextPut: $,].
	^(self integerToString: stream contents size), stream contents


!

descriptionIn: aString at: anInteger

	| start length result |
	start := 1.
	length := 0.
	anInteger timesRepeat: [
		start := start + length.
		length := aString sshLongAt: 1 from: start.
		start := start + 4].
	result := aString copyFrom: start to: start + length - 1.
	^result isEmpty ifTrue: [#()] ifFalse: [result subStrings: $,]!

fromBinary: aStream
	
	| length |
	length := (aStream next: 4) sshLong.
	^(aStream next: length) subStrings: $,!

toBinary: anObject
	"Answer a Collection with binary values of the receiver on <anObject>."

	^self describeCollection: anObject! !

SSHMessageFieldStringCollection initializeAfterLoad!