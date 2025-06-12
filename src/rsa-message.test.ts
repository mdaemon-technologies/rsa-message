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

  describe('Derived Key Encryption (ECDH + PBKDF2)', () => {
    let alice: RSAMessage;
    let bob: RSAMessage;

    beforeEach(() => {
      alice = new RSAMessage();
      bob = new RSAMessage();
    });

    describe('generateECDHKeyPair()', () => {
      test('generates ECDH key pair successfully', async () => {
        const keyPair = await alice.generateECDHKeyPair();
        expect(keyPair.publicKey).toBeTruthy();
        expect(typeof keyPair.publicKey).toBe('string');
      });
    });

    describe('setECDHPublicKey()', () => {
      test('imports and stores ECDH public key successfully', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);
        expect(bob.hasECDHPublicKey('alice')).toBe(true);
      });
    });

    describe('deriveSharedKey()', () => {
      test('derives shared key successfully', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();

        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);

        const aliceSalt = await alice.deriveSharedKey('bob');
        const bobSalt = await bob.deriveSharedKey('alice', aliceSalt);

        expect(alice.hasSharedKey('bob')).toBe(true);
        expect(bob.hasSharedKey('alice')).toBe(true);
        expect(aliceSalt).toEqual(bobSalt);
      });

      test('throws error when ECDH private key not generated', async () => {
        await expect(alice.deriveSharedKey('bob'))
          .rejects.toThrow('ECDH private key not generated');
      });

      test('throws error when other user\'s public key not found', async () => {
        await alice.generateECDHKeyPair();
        await expect(alice.deriveSharedKey('bob'))
          .rejects.toThrow('ECDH public key not found for user: bob');
      });
    });

    describe('encryptWithSharedKey()', () => {
      test('encrypts message with shared key successfully', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();

        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await alice.deriveSharedKey('bob');

        const message = 'Secret shared message';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');        expect(encrypted.salt).toBeInstanceOf(Uint8Array);
        expect(encrypted.encryptedMessage).toBeTruthy();
        expect(encrypted.iv).toBeInstanceOf(Uint8Array);
      });

      test('throws error when shared key not found', async () => {
        await expect(alice.encryptWithSharedKey('message', 'bob'))
          .rejects.toThrow('Shared key not found for user: bob');
      });
    });

    describe('decryptWithSharedKey()', () => {
      test('decrypts message with shared key successfully', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();

        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);

        const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);

        const message = 'Secret shared message';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        const decrypted = await bob.decryptWithSharedKey(encrypted, 'alice');

        expect(decrypted).toBe(message);
      });

      test('throws error when shared key not found', async () => {
        const encrypted = {
          salt: new Uint8Array(16),
          encryptedMessage: new ArrayBuffer(32),
          iv: new Uint8Array(12)
        };

        await expect(bob.decryptWithSharedKey(encrypted, 'alice'))
          .rejects.toThrow('Shared key not found for user: alice');
      });
    });

    describe('exportSharedKeyData() and importSharedKeyData()', () => {
      test('exports and imports shared key data successfully', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();

        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await bob.setECDHPublicKey('alice', aliceKeyPair.publicKey);

        const salt = await alice.deriveSharedKey('bob');
        await bob.deriveSharedKey('alice', salt);

        const message = 'Secret shared message';
        const encrypted = await alice.encryptWithSharedKey(message, 'bob');
        const exported = alice.exportSharedKeyData(encrypted);
        const imported = bob.importSharedKeyData(exported);

        expect(typeof exported).toBe('string');
        expect(imported.salt).toEqual(encrypted.salt);
        expect(imported.iv).toEqual(encrypted.iv);
        expect(new Uint8Array(imported.encryptedMessage)).toEqual(new Uint8Array(encrypted.encryptedMessage));

        const decrypted = await bob.decryptWithSharedKey(imported, 'alice');
        expect(decrypted).toBe(message);
      });
    });

    describe('key management methods', () => {
      test('hasSharedKey() works correctly', async () => {
        expect(alice.hasSharedKey('bob')).toBe(false);
        
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await alice.deriveSharedKey('bob');
        
        expect(alice.hasSharedKey('bob')).toBe(true);
      });

      test('hasECDHPublicKey() works correctly', async () => {
        expect(alice.hasECDHPublicKey('bob')).toBe(false);
        
        const bobKeyPair = await bob.generateECDHKeyPair();
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        
        expect(alice.hasECDHPublicKey('bob')).toBe(true);
      });

      test('removeSharedKey() works correctly', async () => {
        const aliceKeyPair = await alice.generateECDHKeyPair();
        const bobKeyPair = await bob.generateECDHKeyPair();
        
        await alice.setECDHPublicKey('bob', bobKeyPair.publicKey);
        await alice.deriveSharedKey('bob');
        
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
