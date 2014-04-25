


TestCase subclass: #SSHSupportTest
    instanceVariableNames: 'resource '
    classVariableNames: ''
    poolDictionaries: ''!

!SSHSupportTest class publicMethods !

isAbstract

	^self = ##(self)!

resources

	^Set with: SSHSupportTestResource! !

!SSHSupportTest publicMethods !

byteFromBinary: aString

	| value |
	value := 0.
	aString reverse doWithIndex: [:each :index | 
		each = $1 ifTrue: [value := value + (2 raisedTo: index - 1)]].
	^value asCharacter!

defaultSSHConnector

	^resource defaultSSHConnector!

defaultSSHConnectorConnected

	^resource defaultSSHConnectorConnected!

defaultSSHConnectorLogged

	^resource defaultSSHConnectorLogged!

defaultTestHost
	
	^resource defaultTestHost
	
	!

defaultTestPassword

	^resource defaultTestPassword
!

defaultTestPort
	
	^resource defaultTestPort!

defaultTestUser

	^resource defaultTestUser
!

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
	^value
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

setUp
	
	resource := SSHSupportTestResource current! !

SSHSupportTest initializeAfterLoad!


SSHSupportTest subclass: #DiffieHellmanTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!DiffieHellmanTest publicMethods !

defaultDiffieHellman

	^DiffieHellman fromDescription: 'diffie-hellman-group1-sha1'!

defaultKeyLength

	^32!

defaultRandomValue

	^7777!

defaultServerKey

	^#(0 140 42 41 239 193 197 241 105 245 213 16 209 98 113 176 229 28 12 49 49 158 94 205 124 139 169 120 67 19 236 228 42 149 81 132 210 21 103 68 95 16 215 245 16 148 191 189 118 218 119 122 200 43 9 236 240 8 212 147 48 23 38 243 194 206 122 134 140 54 172 169 100 249 174 115 115 101 20 192 77 77 88 189 99 208 50 224 218 158 200 109 121 5 120 136 204 139 31 129 35 25 162 160 210 186 16 183 207 98 180 99 181 19 217 46 47 108 204 40 66 58 170 76 53 77 247 228 183)!

testCorrectKeyNegative
	"Verify whether a negative key is correctly formatted (with a 0 at the beginning)."

	| key generator |
	generator := self defaultDiffieHellman.
	key := generator correctKey: (Array with: 129 asCharacter with: 0 asCharacter with: 0 asCharacter with: 1 asCharacter).
	self assert: (key isKindOf: Collection).
	self assert: key size = 5!

testCorrectKeyPositive
	"Verify whether a negative key is correctly formatted (without a 0 at the beginning)."

	| key generator |
	generator := self defaultDiffieHellman.
	key := generator correctKey: (Array with: 127 asCharacter with: 0 asCharacter with: 0 asCharacter with: 1 asCharacter).
	self assert: (key isKindOf: Collection).
	self assert: key size = 4!

testGenerateKey
	"Verify whether a key generates correctly."

	| key |
	key := self defaultDiffieHellman generateKey: self defaultKeyLength x: self defaultRandomValue.
	self assert: (key isKindOf: Collection).
	self assert: key size >= 127
!

testInitialPrime
	"Verify #initialPrime accessing."

	| prime |
	prime := self defaultDiffieHellman initialPrime.
	self assert: (prime isKindOf: LargeInteger)!

testRaiseToIntegerModulo
	"Verify #raise:toInteger:modulo: operation behaves correctly with some example cases."

	| generator |
	generator := self defaultDiffieHellman.
	self 
		assert: (generator raise: 1 toInteger: 2 modulo: 4) = 1;
		assert: (generator raise: 3 toInteger: 2 modulo: 4) = 1;
		assert: (generator raise: 257 toInteger: 121 modulo: 277) = 143
! !

DiffieHellmanTest initializeAfterLoad!


SSHSupportTest subclass: #EncryptionTest
    instanceVariableNames: 'algorithm '
    classVariableNames: ''
    poolDictionaries: ''!

!EncryptionTest class publicMethods !

isAbstract

	^self = ##(self)! !

EncryptionTest initializeAfterLoad!


EncryptionTest subclass: #RC4EncryptionTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!RC4EncryptionTest publicMethods !

setUp

	algorithm := RC4Encryption new!

testContinuousEncryption
	"Verify whether continuous encryption is enabled.
	 This can be tested, checking than some value is ciphered to a different value the second time."

	| resultA resultB |
	resultA := algorithm key: 'some key'; encrypt: 'test'.
	resultB := algorithm encrypt: 'test'.
	self deny: resultA = resultB
!

testKey
	"Verify whether ciphered value is different when key changes."

	| firstResult secondResult |
	algorithm key: 'abc'.
	firstResult := algorithm encrypt: 'a'.
	algorithm key: 'cba'.
	secondResult := algorithm encrypt: 'a'.
	self deny: firstResult = secondResult!

testKeyLength
	"Verify keyLength accessing."

	self assert: (algorithm keyLength isKindOf: Integer)!

testUnofficialCases
	"Verify RC4 encryption with some example unofficial cases from:
	 http://en.wikipedia.org/wiki/RC4."
	
	| result |
	result := algorithm key: 'Key'; encrypt: 'Plaintext'.
	self assert: ((self integerFromString: result) printStringRadix: 16 showRadix: false) = 'BBF316E8D940AF0AD3'.
	result := algorithm key: 'Wiki'; encrypt: 'pedia'.
	self assert: ((self integerFromString: result) printStringRadix: 16 showRadix: false) = '1021BF0420'.
	result := algorithm key: 'Secret'; encrypt: 'Attack at dawn'.
	self assert: ((self integerFromString: result) printStringRadix: 16 showRadix: false) = '45A01F645FC35B383552544B9BF5'

!

testValidNewInstance
	"Verify whether an RC4Encryption is valid when instanciated #new."
	
	| value |	
	self shouldnt: [value := RC4Encryption new encrypt: 'example'] raise: TestResult error.
	self assert: (value isKindOf: String)! !

RC4EncryptionTest initializeAfterLoad!


SSHSupportTest subclass: #HMACAlgorithmTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!HMACAlgorithmTest class publicMethods !

isAbstract

	^self = ##(self)! !

HMACAlgorithmTest initializeAfterLoad!


HMACAlgorithmTest subclass: #HMACSHA1Test
    instanceVariableNames: 'hmacAlgorithm '
    classVariableNames: ''
    poolDictionaries: ''!

!HMACSHA1Test publicMethods !

_testHashingRFCCase4
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 4 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: ('0102030405060708090a0b0c0d0e0f10111213141516171819' abrAsInteger: 16).
	result := hmacAlgorithm hash: (self stringWith: 205 times: 50).
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = 'E8E99D0F45237D786D6BBAA7965C7808BBFF1A91'

!

_testHashingRFCCase6
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 6 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: (self stringWith: 170 times: 80).
	result := hmacAlgorithm hash: 'Test Using Larger Than Block-Size Key - Hash Key First'.
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = 'AA4AE5E15272D00E95705637CE8A3B55ED402112'

	
!

_testHashingRFCCase7
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 7 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: (self stringWith: 170 times: 80).
	result := hmacAlgorithm hash: 'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data'.
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = 'E8E99D0F45237D786D6BBAA7965C7808BBFF1A91'

	
!

largeString

	^(1 to: 100) inject: '' into: [:total :each | total, each asCharacter asString]!

setUp

	hmacAlgorithm := HMACSHA1 new
										!

shortString

	^'a short string'!

stringWith: value times: length

	^(1 to: length) inject: '' into: [:total :each | total, value asCharacter asString]!

testBasicHash
	"Verify basic hash behaves correctly as a SHA1 hash function."

	| result |
	result := hmacAlgorithm basicHash: 'The quick brown fox jumps over the lazy dog'.
	self assert: result first value = 47.
	self assert: result last value = 18.

	result := hmacAlgorithm basicHash: 'The quick brown fox jumps over the lazy cog'.
	self assert: result first value = 222.
	self assert: result last value = 179



				
!

testBitWiseXorWith
	"Verify #bitWiseXor:with: operation behaves correctly."

	self 
		assert: (hmacAlgorithm bitwiseXor: (self stringWith: 0 times: 1) with: (self stringWith: 0 times: 1)) = (self stringWith: 0 times: 1);
		assert: (hmacAlgorithm bitwiseXor: (self stringWith: 0 times: 10) with: (self stringWith: 0 times: 10)) = (self stringWith: 0 times: 10);
		assert: (hmacAlgorithm bitwiseXor: (self stringWith: 255 times: 1) with: (self stringWith: 1 times: 1)) = (self stringWith: 254 times: 1);
		assert: (hmacAlgorithm bitwiseXor: (self stringWith: 255 times: 10) with: (self stringWith: 1 times: 10)) = (self stringWith: 254 times: 10)!

testHashingRFCCase1
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 1 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: (self stringWith: 11 times: 20).
	result := hmacAlgorithm hash: 'Hi There'.
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = 'B617318655057264E28BC0B6FB378C8EF146BE00'
	
!

testHashingRFCCase2
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 2 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: 'Jefe'.
	result := hmacAlgorithm hash: 'what do ya want for nothing?'.
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = 'EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79'
	
!

testHashingRFCCase3
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 3 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: (self stringWith: 170 times: 20).
	result := hmacAlgorithm hash: (self stringWith: 221 times: 50).
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = '125D7342B9AC11CD91A39AF48AA17B4F63F175D3'
	
!

testHashingRFCCase5
	"Verify whether hashing algorithm HMACSHA1 behaves correctly.
	 Test case 5 from: http://tools.ietf.org/html/rfc2202."

	| result hexResult |
	hmacAlgorithm key: (self stringWith: 12 times: 20).
	result := hmacAlgorithm hash: 'Test With Truncation'.
	hexResult := (self integerFromString: result) printStringRadix: 16 showRadix: false.
	self assert: hexResult = '4C1A03424B55E07FE7F27BE1D58BB9324A9A5A04'

	
!

testKey
	
	self 	
		assert: (hmacAlgorithm key isKindOf: Collection);
		assert: hmacAlgorithm key notEmpty!

testKeyLength
	"Verify key length accessing."

	self assert: (hmacAlgorithm keyLength isKindOf: Integer)!

testPad
	"Verify #pad: method."

	self 
		assert: (hmacAlgorithm pad: self shortString) size = 64;
		assert: (hmacAlgorithm pad: self largeString) size = 64! !

HMACSHA1Test initializeAfterLoad!


SSHSupportTest subclass: #SFTPClientTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPClientTest class publicMethods !

resources
	^Set with: SFTPClientTestResource! !

!SFTPClientTest publicMethods !

defaultFileContents
	
	^resource defaultFileContents
	
	!

defaultFileName
	
	^resource defaultFileName
	
	!

defaultInvalidDirectory
	
	^'invalid-directory'
	
	!

defaultInvalidFileName
	
	^'invalid-filename.txt'
	
	!

defaultSFTPClient

	^resource defaultSFTPClient!

defaultSFTPClientConnected

	^resource defaultSFTPClientConnected!

defaultSFTPClientLogged

	^resource defaultSFTPClientLogged

!

defaultTestDirectory
	
	^resource defaultTestDirectory
	
	!

defaultValidDirectory
	
	^resource defaultValidDirectory
	
	!

setUp
	super setUp.
	resource := SFTPClientTestResource current!

testChangeDirectoryInvalid

	| client |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	self should: [client changeDirectory: self defaultInvalidDirectory] raise: TestResult error!

testChangeDirectoryValid

	| client |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	self shouldnt: [client changeDirectory: self defaultValidDirectory] raise: TestResult error
!

testDisconnect
	"Verify that the client can be disconnected."

	| client |
	client := self defaultSFTPClient.
	self shouldnt: [client disconnect] raise: Error.
	client := self defaultSFTPClientConnected.
	self shouldnt: [client disconnect] raise: Error.
	client := self defaultSFTPClientLogged.
	self shouldnt: [client disconnect] raise: Error!

testDownloadInvalid
	"Verify that an attempt to download an invalid file raises an error."

	| client |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	self should: [client getFile: self defaultInvalidFileName] raise: TestResult error!

testDownloadValid
	"Verify that a file can be downloaded correctly with the client."

	| client fileContents |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	fileContents := client getFile: self defaultFileName.
	client disconnect.
	self assert: (fileContents copyFrom: 1 to: fileContents size - 1) = self defaultFileContents
!

testFileSizeInvalid
	"Verify that trying to retrieve the size of an invalid file name raises an error."

	| client size |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	self should: [client remoteFileSize: self defaultInvalidFileName] raise: TestResult error
!

testFileSizeValid
	"Verify whether the client can retrieve a file size correctly."

	| client size |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	size := client remoteFileSize: client pwd, self defaultFileName.
	self assert: size - 1 = self defaultFileContents size


!

testLoginConnected
	"Verify whether the client can log in."

	| client |
	client := self defaultSFTPClientConnected.
	self shouldnt: [client login: self defaultTestUser password: self defaultTestPassword] raise: Error!

testLoginLogged
	"Verify that a login attempt raises an error when the client is already logged."

	| client |
	client := self defaultSFTPClientLogged.
	self should: [client login: self defaultTestUser password: self defaultTestPassword] raise: TestResult error!

testLoginNotConnected
	"Verify that a login attempt raises an error when the client is not connected."

	| client |
	client := self defaultSFTPClient.
	self should: [client login: self defaultTestUser password: self defaultTestPassword] raise: TestResult error!

testNew
	"Verify the connector can't be instantiated with new (just using accessors)."

	self should: [SFTPClient new] raise: TestResult error!

testPwd
	"Verify the execution of pwd command with an example."

	| client pwd |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	pwd := client pwd.
	self assert: (pwd isKindOf: Collection).
	client changeDirectory: '.'.
	self assert: client pwd = pwd.
	self shouldnt: [client changeDirectory: self defaultValidDirectory] raise: Error.
	self assert: client pwd = (pwd, self defaultValidDirectory, '/')
	
	

!

testUploadInvalid
	"Verify that uploading a file with invalid file name raises an error."

	| client fileContents |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	self 
		should: [client putFile: '2\2\/' data: self defaultFileContents]
		raise: TestResult error!

testUploadValid
	"Verify that the connector can upload a file."

	| client fileContents |
	client := self defaultSFTPClientLogged.
	client changeDirectory: self defaultTestDirectory.
	client putFile: self defaultFileName, '_uploaded' data: self defaultFileContents, '_uploaded'.
	fileContents := client getFile: self defaultFileName, '_uploaded'.
	self assert: (fileContents copyFrom: 1 to: fileContents size) = (self defaultFileContents, '_uploaded')

! !

SFTPClientTest initializeAfterLoad!


SSHSupportTest subclass: #SFTPMessageTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: 'SFTPConstants '!

!SFTPMessageTest publicMethods !

checkSimmetricConversion: message with: newMessage
	"Check whether <message> and <newMessage> are equal."

	self 
		assert: message type = newMessage type;
		assert: message contents = newMessage contents
!

defaultMessage
	"Answer a default message for the tests of the receiver."
	
	^SFTPMessage messageOpenWriteForced: 'somefile.txt'!

defaultMessages
	"Answer a default message for the tests of the receiver."
	
	^OrderedCollection new
			add: (SFTPMessage messageOpenWriteForced: 'somefile.txt');
			add: (SFTPMessage messageCloseHandle: 1);
			add: (SFTPMessage messageFileStat: 'somefile.txt');
			add: (SFTPMessage messageOpenDir: 'somefile.txt');
			add: (SFTPMessage messageOpenRead: 'somefile.txt');
			add: (SFTPMessage messageOpenWriteForced: 'somefile.txt');
			add: (SFTPMessage messageRealPath: 'somefile.txt');
			add: (SFTPMessage messageSFTPInit);
			add: (SFTPMessage messageReadHandle: 1 read: 2 from: 3 windowSize: 4);
			add: (SFTPMessage messageWriteHandle: 1 flag: 2 sentBytes: 3 bytes: 4);
			yourself
			!

testContents
	"Verify whether a SFTPMessage can retrieve its binary contents."

	| message |
	message := self defaultMessage.
	self assert: (message contents isKindOf: Collection).
	self assert: message contents notEmpty
	!

testRequestId
	"Verify whether request id affects to binary contents of a SFTPMessage."

	| message contents |
	message := self defaultMessage.
	contents := message contents.
	self assert: message requestId isNil.
	self assert: message requestIdDescription = ''.
	message requestId: 1.
	self assert: message requestId = 1.
	self assert: message requestIdDescription = (self integerToString: 1).
	self deny: message contents = contents
	
	!

testSimmetricConversionWithoutRequestId
	"Verify whether the instanciation of a SFTPMessage from the binary contents of another equals the propper.
	#Note: The first 4 bytes of the contents of an SFTPMessage are the contents length, which has to be stripped
			   when creating a new instance with #fromBytes:requestId:."

	| newMessage contents |
	self defaultMessages do: [:message | 
		contents := message contents copyFrom: 5 to: message contents size.
		newMessage := SFTPMessage fromBytes: contents requestId: nil.
		self checkSimmetricConversion: message with: newMessage]!

testSimmetricConversionWithRequestId
	"Verify whether the instanciation of a SFTPMessage from the binary contents of another equals the propper.
	#Note: The first 4 bytes of the contents of an SFTPMessage are the contents length, which has to be stripped
			   when creating a new instance with #fromBytes:requestId:.

				 Assigning request id put in evidence that instanciation of a message with #fromBytes:requestId does not
				 fill the requestId of the SFTPMessage."

	| newMessage contents |
	self defaultMessages do: [:message | 
		message requestId: 1.
		contents := message contents copyFrom: 5 to: message contents size.
		newMessage := SFTPMessage fromBytes: contents requestId: 1.
		newMessage requestId: 1.
		self checkSimmetricConversion: message with: newMessage]!

testType
	"Verify the type of an SFTPMessage."

	| message |
	message := self defaultMessage.
	self assert: (message type isKindOf: Number)! !

SFTPMessageTest initializeAfterLoad!


SSHSupportTest subclass: #SSH2ConnectorTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2ConnectorTest publicMethods !

testCommandExecution
	"Verify whether the connector can execute a remote command and retrieve the correct result."

	| connector result |
	connector := self defaultSSHConnectorLogged.
	result := connector executeCommand: 'echo "test data"'.
	self assert: result size = 10
	!

testCommandsExecution
	"Verify whether the connector can execute multiple commands."

	| connector result |
	connector := self defaultSSHConnectorLogged.
	connector executeCommand: 'echo "test data"'.
	self shouldnt: [connector executeCommand: 'echo "test data"'] raise: TestResult error

	!

testCreateCookie
	"Verify whether an SSH2Connector generates a proper client cookie."

	| cookie |
	cookie := self defaultSSHConnector createCookie.
	self assert: (cookie isKindOf: Collection).
	self assert: cookie size = 16!

testDisconnect
	"Verify whether the connector can be disconnected."

	| client |
	client := self defaultSSHConnector.
	self shouldnt: [client disconnect] raise: TestResult error.
	client := self defaultSSHConnectorConnected.
	self shouldnt: [client disconnect] raise: TestResult error.
	client := self defaultSSHConnectorLogged.
	self shouldnt: [client disconnect] raise: TestResult error

!

testHostName
	"Verify hostName accessor."

	| client |
	client := self defaultSSHConnector.
	self assert: (client hostName isKindOf: String).
	self assert: client hostName = self defaultTestHost!

testLogin
	"Verify whether the connector can log in."

	| client |
	client := self defaultSSHConnectorConnected.
	self shouldnt: [client login: self defaultTestUser password: self defaultTestPassword] raise: TestResult error
!

testLoginNotConnected
	"Verify that a login intent raises an error when the connector is not connected."

	| client |
	client := self defaultSSHConnector.
	self should: [client login: self defaultTestUser password: self defaultTestPassword] raise: TestResult error!

testPortNumber
	"Verify portNumber accessor."

	| client |
	client := self defaultSSHConnector.
	self assert: (client portNumber isKindOf: Integer).
	self assert: client portNumber = self defaultTestPort!

testStartup
	"Verify startup process."

	| client |
	client := self defaultSSHConnector.
	self shouldnt: [client startup] raise: TestResult error
! !

SSH2ConnectorTest initializeAfterLoad!


SSHSupportTest subclass: #SSH2MessageTest
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSH2MessageTest publicMethods !

checkSimmetricConversion: message with: newMessage
	"Check whether <message> and <newMessage> are equal."

	self 
		assert: message type = newMessage type;
		assert: message contents = newMessage contents
!

defaultMessage
	"Answer a default message for the tests of the receiver."
	
	^SSH2Message messageCloseChannel: 1!

defaultMessages
	"Answer a default message for the tests of the receiver."
	
	^OrderedCollection new
			add: (SSH2Message messageAuthorizationRequestUser: 'a' password: 'b');
			add: (SSH2Message messageChannel: 1 data: 'a');
			add: (SSH2Message messageChannelRequest: 1 command: 'b');
			add: (SSH2Message messageCloseChannel: 1);
			add: (SSH2Message messageDisconnectReason: 1);
			add: (SSH2Message messageKeyExchangeDHInit: 'abc');
			add: (SSH2Message messageNewKeys);
			add: (SSH2Message messageOpenChannelSession: 1 windowSize: 2 packetSize: 3);
			add: (SSH2Message messageSFTPChannelRequest: 1);
			add: (SSH2Message messageSSHLoginRequest);
			add: (SSH2Message messageWindowAdjust: 1 size: 2);
			yourself
			!

testContents
	"Verify contents of an example message."

	| contents |
	contents := self defaultMessage contents.
	self assert: (contents isKindOf: Collection).
	self assert: contents notEmpty!

testSimmetricConversion
	"Verify whether the instanciation of a SFTPMessage from the binary contents of another equals the propper."

	| newMessage contents |
	self defaultMessages do: [:message | 
		contents := message contents.
		newMessage := SSH2Message fromBytes: contents.
		self checkSimmetricConversion: message with: newMessage]!

testType
	"Verify type accessor."

	self assert: (self defaultMessage type isKindOf: Integer)! !

SSH2MessageTest initializeAfterLoad!




TestResource subclass: #SSHSupportTestResource
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SSHSupportTestResource publicMethods !

defaultSSHConnector

	^SSH2Connector 
		onHost: self defaultTestHost
		port: self defaultTestPort!

defaultSSHConnectorConnected

	^SSH2Connector 
		startupOnHost: self defaultTestHost
		port: self defaultTestPort!

defaultSSHConnectorLogged

	^self defaultSSHConnectorConnected
		login: self defaultTestUser password: self defaultTestPassword;
		yourself
!

defaultTestHost
	
	^IniFile valueAtKey: 'testEnvironmentHost'
	!

defaultTestPassword

	^IniFile valueAtKey: 'testEnvironmentPassword'
!

defaultTestPort
	
	^(IniFile valueAtKey: 'testEnvironmentPort') asNumber
	!

defaultTestUser

	^IniFile valueAtKey: 'testEnvironmentUser'
! !

SSHSupportTestResource initializeAfterLoad!


SSHSupportTestResource subclass: #SFTPClientTestResource
    instanceVariableNames: ''
    classVariableNames: ''
    poolDictionaries: ''!

!SFTPClientTestResource publicMethods !

defaultFileContents
	
	^'abc'
	
	!

defaultFileName
	
	^'samplefile.txt'
	
	!

defaultSFTPClient

	^SFTPClient onHost: self defaultTestHost port: self defaultTestPort!

defaultSFTPClientConnected

	^SFTPClient startupOnHost: self defaultTestHost port: self defaultTestPort!

defaultSFTPClientLogged

	^self defaultSFTPClientConnected
		login: self defaultTestUser password: self defaultTestPassword;
		yourself
!

defaultTestDirectory
	
	^'UnitTests'
	
	!

defaultValidDirectory
	
	^'ValidDirectory'
	!

deleteTestEnvironment

	self defaultSSHConnectorLogged
		executeCommand: 'cd';
		executeCommand: 'rm -R ', self defaultTestDirectory
	!

prepareTestEnvironment

	self defaultSSHConnectorLogged
		executeCommand: 'cd';
		executeCommand: 'mkdir ', self defaultTestDirectory;
		executeCommand: 'mkdir ', self defaultTestDirectory, '/', self defaultValidDirectory;
		executeCommand: 'cd ', self defaultTestDirectory;
		executeCommand: 'print ', $" asString, self defaultFileContents, $" asString, 
										' > ', self defaultTestDirectory, '/', self defaultFileName
		
	!

setUp

	super setUp.
	self prepareTestEnvironment
!

tearDown

	super tearDown.
	self deleteTestEnvironment! !

SFTPClientTestResource initializeAfterLoad!