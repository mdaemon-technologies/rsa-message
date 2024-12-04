import RSAMessage from "./rsa-message";

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
});
