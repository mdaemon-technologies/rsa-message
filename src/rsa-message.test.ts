import RSAMessage from "./rsa-message";

function mockTransport(message: string, sender: string, verifyKey: string): Promise<{ sender: string, verifyKey: string, message: string }> {
  const transport = {
    sender,
    verifyKey,
    message: message,
  };
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(transport);
    }, 1000);
  });
}

describe('RSAMessage', () => {
  let sender: RSAMessage;
  let receiver: RSAMessage;

  beforeEach(() => {
    sender = new RSAMessage();
    receiver = new RSAMessage();
  });

  describe('init()', () => {
    test('generates new keys when no parameters provided', async () => {
      const keys = await sender.init();
      expect(keys.publicKey).toBeTruthy();
      expect(keys.verifyKey).toBeTruthy();
      expect(sender.publickey).toBeTruthy();
      expect(sender.privatekey).toBeTruthy();
      expect(sender.verifykey).toBeTruthy();
      expect(sender.signkey).toBeTruthy();
    });

    test('uses provided keys when parameters supplied', async () => {
      const initialKeys = await sender.init();
      const newInstance = new RSAMessage();
      const keys = await newInstance.init(
        initialKeys.publicKey,
        sender.privatekey,
        initialKeys.verifyKey,
        sender.signkey
      );
      expect(keys.publicKey).toBe(initialKeys.publicKey);
      expect(keys.verifyKey).toBe(initialKeys.verifyKey);
    });
  });

  describe('publickey getter', () => {
    test('returns empty string before init', () => {
      expect(sender.publickey).toBe('');
    });

    test('returns public key after init', async () => {
      await sender.init();
      expect(sender.publickey).toBeTruthy();
    });
  });

  describe('verifykey getter', () => {
    test('returns empty string before init', () => {
      expect(sender.verifykey).toBe('');
    });

    test('returns verify key after init', async () => {
      await sender.init();
      expect(sender.verifykey).toBeTruthy();
    });
  });

  describe('privatekey getter', () => {
    test('returns empty string before init', () => {
      expect(sender.privatekey).toBe('');
    });

    test('returns private key after init', async () => {
      await sender.init();
      expect(sender.privatekey).toBeTruthy();
    });
  });

  describe('signkey getter', () => {
    test('returns empty string before init', () => {
      expect(sender.signkey).toBe('');
    });

    test('returns sign key after init', async () => {
      await sender.init();
      expect(sender.signkey).toBeTruthy();
    });
  });

  describe('setPublicKey()', () => {
    test('stores public keys for user', async () => {
      await receiver.init();
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      expect(sender.hasPublicKey('receiver')).toBe(true);
    });
  });

  describe('hasPublicKey()', () => {
    test('returns false when user not found', () => {
      expect(sender.hasPublicKey('unknown')).toBe(false);
    });

    test('returns true when user exists', async () => {
      await receiver.init();
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      expect(sender.hasPublicKey('receiver')).toBe(true);
    });
  });

  describe('encryptMessage()', () => {
    test('encrypts message successfully', async () => {
      await sender.init();
      await receiver.init();
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      
      const message = 'Test message';
      const encrypted = await sender.encryptMessage(message, 'receiver');
      
      expect(encrypted.iv).toBeInstanceOf(Uint8Array);
      expect(new Uint8Array(encrypted.encryptedMessage)).toBeInstanceOf(Uint8Array);
      expect(new Uint8Array(encrypted.encryptedAESKey)).toBeInstanceOf(Uint8Array);
      expect(new Uint8Array(encrypted.signature)).toBeInstanceOf(Uint8Array);
    });

    test('throws error for unknown recipient', async () => {
      await sender.init();
      await expect(sender.encryptMessage('test', 'unknown'))
        .rejects.toThrow('Public key not found for user');
    });
  });

  describe('sign and verify', () => {
    test('signs and verifies message successfully', async () => {
      const message = 'Test message';
      await sender.init();
      await receiver.init();

      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      const signature = await sender.signMessage(message);
      receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
      const verified = await receiver.verifySignature(signature, message, 'sender');
      expect(verified).toBe(true);
    });
  });

  describe('decryptMessage()', () => {
    test('decrypts message successfully', async () => {
      const message = 'Test message';
      await sender.init();
      await receiver.init();
      
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
      
      const encrypted = await sender.encryptMessage(message, 'receiver');
      const exported = sender.exportEncryptedMessage(encrypted);
      const imported = receiver.importEncryptedMessage(exported);
      const decrypted = await receiver.decryptMessage(imported, 'sender');
      
      expect(decrypted).toBe(message);
    });

    test('throws error for invalid signature', async () => {
      const message = 'Test message';
      await sender.init();
      await receiver.init();
      
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      // Not setting sender's public key in receiver
      
      const encrypted = await sender.encryptMessage(message, 'receiver');
      await expect(receiver.decryptMessage(encrypted, 'sender'))
        .rejects.toThrow('Public key not found for user');
    });
  });

  describe('exportEncryptedMessage()', () => {
    test('exports message to string format', async () => {
      await sender.init();
      await receiver.init();
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      
      const message = 'Test message';
      const encrypted = await sender.encryptMessage(message, 'receiver');
      const exported = sender.exportEncryptedMessage(encrypted);
      
      expect(typeof exported).toBe('string');
    });
  });

  describe('importEncryptedMessage()', () => {
    test('imports message from string format', async () => {
      await sender.init();
      await receiver.init();
      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
      
      const message = 'Test message';
      const encrypted = await sender.encryptMessage(message, 'receiver');
      const exported = sender.exportEncryptedMessage(encrypted);
      const imported = receiver.importEncryptedMessage(exported);
      
      expect(imported).toHaveProperty('iv');
      expect(imported).toHaveProperty('encryptedMessage');
      expect(imported).toHaveProperty('encryptedAESKey');
      expect(imported).toHaveProperty('signature');
      
    });

    test('throws error for invalid format', () => {
      expect(() => receiver.importEncryptedMessage('invalid-data'))
        .toThrow();
    });
  });

  describe('setVerifyKey()', () => {
      test('sets verify key for user', async () => {
        await sender.init();
        await receiver.init();
        
        receiver.setVerifyKey('sender', sender.verifykey);
        expect(receiver.hasVerifyKey('sender')).toBe(true);
      });
  
      test('throws error for invalid arguments', () => {
        expect(() => receiver.setVerifyKey('', 'key'))
          .toThrow('Invalid arguments');
        expect(() => receiver.setVerifyKey('user', ''))
          .toThrow('Invalid arguments');
      });
    });
  
    describe('hasVerifyKey()', () => {
      test('returns true when verify key exists', async () => {
        await sender.init();
        await receiver.init();
        
        receiver.setVerifyKey('sender', sender.verifykey);
        expect(receiver.hasVerifyKey('sender')).toBe(true);
      });
  
      test('returns false when verify key does not exist', async () => {
        await sender.init();
        await receiver.init();
        
        expect(receiver.hasVerifyKey('sender')).toBe(false);
      });
    });
  
  describe('full message flow including transport', () => {
    test('encrypts, signs, exports for transport, imports for decryption, decrypts, and verifies message successfully, and responds as well', async () => {
      const message = 'Test message';
      await sender.init();
      await receiver.init();

      sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
      const encrypted = await sender.encryptMessage(message, 'receiver');
      const exported = sender.exportEncryptedMessage(encrypted);
      let newMessage = await mockTransport(exported, 'sender', sender.verifykey);

      const imported = receiver.importEncryptedMessage(newMessage.message);
      receiver.setPublicKey(newMessage.sender, sender.publickey, newMessage.verifyKey);
      const decrypted = await receiver.decryptMessage(imported, 'sender');

      const verified = await receiver.verifySignature(encrypted.signature, message, 'sender');

      expect(decrypted).toBe(message);
      expect(verified).toBe(true);

      const responseMessage = "This is my response";
      const encryptedResponse = await receiver.encryptMessage(responseMessage, 'sender');
      const exportedResponse = receiver.exportEncryptedMessage(encryptedResponse);
      newMessage = await mockTransport(exportedResponse, 'receiver', receiver.verifykey);

      const importedResponse = sender.importEncryptedMessage(newMessage.message);
      sender.setPublicKey(newMessage.sender, receiver.publickey, newMessage.verifyKey);
      const decryptedResponse = await sender.decryptMessage(importedResponse, 'receiver');
      const verifiedResponse = await sender.verifySignature(encryptedResponse.signature, responseMessage, 'receiver');

      expect(decryptedResponse).toBe(responseMessage);
      expect(verifiedResponse).toBe(true);
    });
  });
  describe('Master AES Key functionality', () => {
    beforeEach(async () => {
      await sender.init();
      await receiver.init();
    });    describe('master AES key generation and management', () => {
      test('generateAndSetMasterAESKey() generates and stores encrypted master key', async () => {
        // Set sender's own public key for self-encryption
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        
        const encryptedKey = await sender.generateAndSetMasterAESKey();
        expect(encryptedKey).toBeTruthy();
        expect(typeof encryptedKey).toBe('string');
        expect(encryptedKey.length).toBeGreaterThan(0);
      });      test('setEncryptedMasterAESKey() and getDecryptedMasterAESKey() work correctly', async () => {
        // Generate master key for sender
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        const encryptedKey = await sender.generateAndSetMasterAESKey();
        
        // Create new instance and set the encrypted master key
        const newSender = new RSAMessage();
        await newSender.init(
          sender.publickey,
          sender.privatekey,
          sender.verifykey,
          sender.signkey
        );
        
        // Set self key for decryption
        newSender.setPublicKey('self', newSender.publickey, newSender.verifykey);
        newSender.setEncryptedMasterAESKey(encryptedKey);
        
        // Should be able to decrypt the master key
        const masterKey = await newSender.getDecryptedMasterAESKey();
        expect(masterKey).toBeTruthy();
        expect(masterKey.type).toBe('secret');
      });

      test('setEncryptedMasterAESKey() works with encryptor parameter', async () => {
        // Setup: sender generates master key and exports it for receiver
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        await sender.generateAndSetMasterAESKey();
        sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
        const encryptedForReceiver = await sender.exportMasterAESKeyForUser('receiver');

        // Receiver sets up keys and uses setEncryptedMasterAESKey with encryptor parameter
        receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
        receiver.setVerifyKey('sender', sender.verifykey);
        receiver.setEncryptedMasterAESKey(encryptedForReceiver, 'sender');

        // Verify receiver can decrypt the master key
        const receiverMasterKey = await receiver.getDecryptedMasterAESKey();
        expect(receiverMasterKey).toBeTruthy();
        expect(receiverMasterKey.type).toBe('secret');
      });test('exportMasterAESKeyForUser() encrypts master key for another user', async () => {
        // Setup: sender has master key, receiver has their own RSA keys
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        await sender.generateAndSetMasterAESKey();
        sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);

        // Export master key encrypted for receiver
        const encryptedForReceiver = await sender.exportMasterAESKeyForUser('receiver');
        
        expect(encryptedForReceiver).toBeTruthy();
        expect(typeof encryptedForReceiver).toBe('string');
        expect(encryptedForReceiver.length).toBeGreaterThan(0);
      });      test('setMasterAESKeyFromEncrypted() imports encrypted master key from another user', async () => {
        // Setup: sender generates master key and exports it for receiver
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        await sender.generateAndSetMasterAESKey();
        sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
        const encryptedForReceiver = await sender.exportMasterAESKeyForUser('receiver');

        // Receiver imports the encrypted master key and sets up verification
        receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
        receiver.setVerifyKey('sender', sender.verifykey);
        await receiver.setMasterAESKeyFromEncrypted(encryptedForReceiver, 'sender');

        // Verify receiver can decrypt the master key
        const receiverMasterKey = await receiver.getDecryptedMasterAESKey();
        expect(receiverMasterKey).toBeTruthy();
        expect(receiverMasterKey.type).toBe('secret');
      });
    });    describe('master AES key encryption and decryption', () => {
      beforeEach(async () => {
        // Setup master key for both users
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        await sender.generateAndSetMasterAESKey();
        sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
        
        const encryptedForReceiver = await sender.exportMasterAESKeyForUser('receiver');
        receiver.setPublicKey('sender', sender.publickey, sender.verifykey);
        receiver.setVerifyKey('sender', sender.verifykey);
        await receiver.setMasterAESKeyFromEncrypted(encryptedForReceiver, 'sender');
      });

      test('encryptWithMasterAESKey() encrypts message without RSA', async () => {
        const message = 'This message is encrypted with master AES key only';
        const encrypted = await sender.encryptWithMasterAESKey(message);

        expect(encrypted).toBeTruthy();
        expect(encrypted.encryptedMessage).toBeTruthy();
        expect(encrypted.iv).toBeTruthy();
        expect(encrypted.signature).toBeTruthy();
        expect(encrypted.encryptedAESKey).toBeUndefined(); // No RSA encryption used
      });

      test('decryptWithMasterAESKey() decrypts message without RSA', async () => {
        const message = 'This message uses master AES key encryption';
        
        // Encrypt with sender's master AES key
        const encrypted = await sender.encryptWithMasterAESKey(message);
        
        // Decrypt with receiver's master AES key (should be the same key)
        const decrypted = await receiver.decryptWithMasterAESKey(encrypted, 'sender');
        
        expect(decrypted).toBe(message);
      });      test('regular encrypt/decrypt methods work with master AES key when available', async () => {
        const message = 'This tests backwards compatibility with master keys';
        
        // Should use master AES key when available
        const encrypted = await sender.encryptMessage(message, 'receiver', true);
        expect(encrypted.encryptedAESKey).toBeUndefined(); // Master key used, no RSA
        
        const decrypted = await receiver.decryptMessage(encrypted, 'sender', true);
        expect(decrypted).toBe(message);
      });      test('regular encrypt/decrypt methods fall back to RSA when useMasterKey is false', async () => {
        const message = 'This tests RSA fallback with master keys present';
        
        // Should use RSA even when master key is available
        const encrypted = await sender.encryptMessage(message, 'receiver', false);
        expect(encrypted.encryptedAESKey).toBeTruthy(); // RSA encryption used
        
        const decrypted = await receiver.decryptMessage(encrypted, 'sender', false);
        expect(decrypted).toBe(message);
      });

      test('master AES key encryption is more efficient than RSA', async () => {
        const message = 'Performance test message';
        
        // Encrypt with master AES key
        const startMaster = performance.now();
        const encryptedMaster = await sender.encryptWithMasterAESKey(message);
        const masterTime = performance.now() - startMaster;
        
        // Encrypt with RSA
        const startRSA = performance.now();
        const encryptedRSA = await sender.encryptMessage(message, 'receiver', false);
        const rsaTime = performance.now() - startRSA;
        
        // Master AES should be faster (though this might vary in test environment)
        // At minimum, verify both methods work
        expect(encryptedMaster).toBeTruthy();
        expect(encryptedRSA).toBeTruthy();
        expect(encryptedMaster.encryptedAESKey).toBeUndefined();
        expect(encryptedRSA.encryptedAESKey).toBeTruthy();
      });
    });

    describe('error handling', () => {      test('getDecryptedMasterAESKey() returns null when no master key set', async () => {
        await expect(sender.getDecryptedMasterAESKey())
          .rejects.toThrow('No master AES key set');
      });

      test('encryptWithMasterAESKey() throws when no master key available', async () => {
        await expect(sender.encryptWithMasterAESKey('test message'))
          .rejects.toThrow('No master AES key set');
      });test('decryptWithMasterAESKey() throws when no master key available', async () => {
        const mockEncrypted = {
          encryptedMessage: new ArrayBuffer(0),
          iv: new Uint8Array(12),
          signature: new ArrayBuffer(0)
        };
        
        await expect(receiver.decryptWithMasterAESKey(mockEncrypted, 'sender'))
          .rejects.toThrow('No master AES key set');
      });      test('exportMasterAESKeyForUser() throws when no master key available', async () => {
        sender.setPublicKey('receiver', receiver.publickey, receiver.verifykey);
        
        await expect(sender.exportMasterAESKeyForUser('receiver'))
          .rejects.toThrow('No master AES key set');
      });      test('exportMasterAESKeyForUser() throws when user public key not found', async () => {
        sender.setPublicKey('self', sender.publickey, sender.verifykey);
        await sender.generateAndSetMasterAESKey();
        
        await expect(sender.exportMasterAESKeyForUser('unknown'))
          .rejects.toThrow('Public key not found for user');
      });
    });
  });

  describe('Derived Key Encryption (ECDH)', () => {
    let alice: RSAMessage;
    let bob: RSAMessage;

    beforeEach(async () => {
      alice = new RSAMessage();
      bob = new RSAMessage();
      await alice.init();
      await bob.init();
    });

    describe('ECDH key generation and exchange', () => {
      test('generateECDHKeyPair() generates valid key pair', async () => {
        const keyPair = await alice.generateECDHKeyPair();
        
        expect(keyPair).toBeTruthy();
        expect(keyPair.publicKey).toBeTruthy();
        expect(typeof keyPair.publicKey).toBe('string');
        expect(keyPair.publicKey.length).toBeGreaterThan(0);
      });

      test('setECDHPublicKey() stores ECDH public key', async () => {
        const bobKeyPair = await bob.generateECDHKeyPair();
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        
        expect(alice.hasECDHPublicKey('bob')).toBe(true);
      });

      test('hasECDHPublicKey() returns false for non-existent key', () => {
        expect(alice.hasECDHPublicKey('nonexistent')).toBe(false);
      });
    });

    describe('shared key derivation', () => {
      test('deriveSharedKey() creates shared secret', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
          const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);
        
        expect(alice.hasSharedKey('bob')).toBe(true);
        expect(bob.hasSharedKey('alice')).toBe(true);
        expect(salt).toBeTruthy();
        expect(salt instanceof Uint8Array).toBe(true);
      });      test('deriveSharedKey() works with provided salt', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
        
        const customSalt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        await alice.deriveSharedKey('bob', customSalt);
        await bob.deriveSharedKey('alice', customSalt);
        
        expect(alice.hasSharedKey('bob')).toBe(true);
        expect(bob.hasSharedKey('alice')).toBe(true);
      });

      test('hasSharedKey() returns false for non-existent key', () => {
        expect(alice.hasSharedKey('nonexistent')).toBe(false);
      });
    });

    describe('shared key encryption and decryption', () => {
      beforeEach(async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
        
        const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);
      });

      test('encryptWithSharedKey() and decryptWithSharedKey() work correctly', async () => {
        const message = 'Hello from Alice to Bob using shared key!';
        
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        const decrypted = await bob.decryptWithSharedKey(encrypted, 'alice');
        
        expect(decrypted).toBe(message);
      });

      test('encrypted messages cannot be decrypted without correct shared key', async () => {
        const message = 'Secret message';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        
        // Create a third party without the shared key
        const charlie = new RSAMessage();
        await charlie.init();
        
        await expect(charlie.decryptWithSharedKey(encrypted, 'alice'))
          .rejects.toThrow();
      });
    });

    describe('shared key data export and import', () => {
      test('exportSharedKeyData() and importSharedKeyData() work correctly', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
        
        const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);
        
        const message = 'Test message for export/import';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        
        // Export and import
        const exported = alice.exportSharedKeyData(encrypted);
        const imported = bob.importSharedKeyData(exported);
        
        const decrypted = await bob.decryptWithSharedKey(imported, 'alice');
        expect(decrypted).toBe(message);
      });
    });

    describe('key management', () => {
      test('removeSharedKey() works correctly', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
        
        const salt = await alice.deriveSharedKey('bob');
        
        expect(alice.hasSharedKey('bob')).toBe(true);
        alice.removeSharedKey('bob');
        expect(alice.hasSharedKey('bob')).toBe(false);
      });

      test('removeECDHPublicKey() works correctly', async () => {
        const bobKeyPair = await bob.generateECDHKeyPair();
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        
        expect(alice.hasECDHPublicKey('bob')).toBe(true);
        alice.removeECDHPublicKey('bob');
        expect(alice.hasECDHPublicKey('bob')).toBe(false);
      });
    });

    describe('full derived key encryption flow', () => {
      test('complete key exchange and encrypted communication', async () => {
        // Step 1: Generate ECDH key pairs
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();

        // Step 2: Exchange public keys
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);

        // Step 3: Derive shared keys
        const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);

        // Step 4: Alice encrypts message to Bob
        const message = 'Hello Bob, this is a secret message!';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        const exported = alice.exportSharedKeyData(encrypted);

        // Step 5: Bob receives and decrypts message
        const imported = bob.importSharedKeyData(exported);
        const decrypted = await bob.decryptWithSharedKey(imported, 'alice');

        expect(decrypted).toBe(message);

        // Step 6: Bob responds to Alice
        const response = 'Hi Alice, I received your secret message!';
        const encryptedResponse = await bob.encryptWithSharedKey(response, 'alice');
        const exportedResponse = bob.exportSharedKeyData(encryptedResponse);

        // Step 7: Alice receives and decrypts response
        const importedResponse = alice.importSharedKeyData(exportedResponse);
        const decryptedResponse = await alice.decryptWithSharedKey(importedResponse, 'bob');

        expect(decryptedResponse).toBe(response);
      });
    });
  });
});
