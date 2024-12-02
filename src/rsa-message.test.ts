
import RSAMessage from './rsa-message';

describe('RSAMessage', () => {
  let sender: RSAMessage;
  let receiver: RSAMessage;

  beforeEach(() => {
    sender = new RSAMessage();
    receiver = new RSAMessage();
  });

  test('initializes with empty keys', () => {
    expect(sender.publickey).toBe('');
    expect(sender.privatekey).toBe('');
  });

  test('generates new keypair on init', async () => {
    const publicKey = await sender.init();
    expect(publicKey).toBeTruthy();
    expect(typeof publicKey).toBe('string');
  });

  test('encrypts and decrypts message successfully', async () => {
    const message = 'Test message';
    
    // Setup keys
    const senderPublicKey = await sender.init();
    const receiverPublicKey = await receiver.init();
    
    // Exchange public keys
    sender.setPublicKey('receiver', receiverPublicKey);
    receiver.setPublicKey('sender', senderPublicKey);
    
    // Encrypt and decrypt
    const encrypted = await sender.encryptMessage(message, 'receiver');
    const decrypted = await receiver.decryptMessage(encrypted, 'sender');
    
    expect(decrypted).toBe(message);
  });

  test('fails encryption with missing public key', async () => {
    await sender.init();
    const message = 'Test message';

    await expect(async () => {
      await sender.encryptMessage(message, 'unknown');
    }).rejects.toThrow('Public key not found for user');
  });

  test('fails decryption with missing public key', async () => {
    await sender.init();
    await receiver.init();
    
    const message = 'Test message';
    sender.setPublicKey('receiver', receiver.publickey);
    
    const encrypted = await sender.encryptMessage(message, 'receiver');
    
    await expect(async () => {
      await receiver.decryptMessage(encrypted, 'unknown');
    }).rejects.toThrow('Public key not found for user');
  });

  test('exports and imports encrypted message', async () => {
    const message = 'Test message';
    
    // Setup keys
    const senderPublicKey = await sender.init();
    const receiverPublicKey = await receiver.init();
    
    // Exchange public keys
    sender.setPublicKey('receiver', receiverPublicKey);
    receiver.setPublicKey('sender', senderPublicKey);
    
    // Encrypt
    const encrypted = await sender.encryptMessage(message, 'receiver');
    
    // Export to transportable format
    const exported = sender.exportEncryptedMessage(encrypted);
    expect(typeof exported).toBe('string');
    
    // Import from transportable format
    const imported = receiver.importEncryptedMessage(exported);
    expect(imported).toHaveProperty('iv');
    expect(imported).toHaveProperty('encryptedMessage');
    expect(imported).toHaveProperty('encryptedAESKey');
    expect(imported).toHaveProperty('signature');
    
    // Verify decryption still works
    const decrypted = await receiver.decryptMessage(imported, 'sender');
    expect(decrypted).toBe(message);
  });

  test('exported message is base64 encoded', async () => {
    const message = 'Test message';
    await sender.init();
    await receiver.init();
    sender.setPublicKey('receiver', receiver.publickey);
    
    const encrypted = await sender.encryptMessage(message, 'receiver');
    const exported = sender.exportEncryptedMessage(encrypted);
    
    // Verify it's valid base64
    expect(() => atob(exported)).not.toThrow();
  });
});