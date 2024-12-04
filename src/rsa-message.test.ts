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
      await sender.init(
        "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlIjoiQVFBQiIsImV4dCI6dHJ1ZSwia2V5X29wcyI6WyJlbmNyeXB0Il0sImt0eSI6IlJTQSIsIm4iOiIzZTN1WHA4NnQyY25teXFjZG8tZEFBbExja0U2cXZTbG5kOVFYNUh2M3FUMkF6dld5cndUWS1Ka0xLRHo5MWpCZFhPYWtXbi1iY1lpN1FrN2JGS3JjZUZKbFE2cFczWkh4dmxoaEpQaHpRT2QzWlltanYtMDdpRE5TNDRMeTFHeHQ5ZTRIS0htNTlxbXNpM2hmUEt1aG56T19GSnFycTNWZkx1WFNtWklzdWE4Slp5SmJ5VmF1dHFqUnBIODFjNk1ySjFDQXdxcGV5dEs1bTJuTGg4dVZKMGwyalFxeUZjaElzem8xMUhCYmFrbVVtUG4xWHp3aDNWcjh2bk5DTXhaTTBBNVRLMEJVajlUNmVwd1Jqa1YyNzJFSzBhYkdGb3lzd0dBSFBDek5uRy1LSjlwQ2RvWmNRbE9Mb3lHX2lmdmk2bU5hTmlISEJ3ek9xLTZyTF9hSHcifQ==", 
        "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJkIjoiS0VGQnRSRWQxZW1Vb2cwYkgxaFNhcERGQ2g3eDFOT1dmT25tU3NlT1lteTZvUUNJSl9Md2MzUTdwbXExaGY2bjdMV0E2bkoyNzVONmYxTm0zM0dwWG5rMlh4NnZNb05rWnAtU2hEbE13bUt2RG1QdmI0M0xWRXhINExZTnhwMzFaZnJ2anVZQkc3b3A5WFRrQzBWN3liSTIyMGJaeWdDSEVsNTJoVXpEVUF1NnNBQlNvVUdoaUxUVHlITTE5VVNpMXRZWU5CeXhKMktVOURvNXpiTjJvYlVKZlZXNDQ3bnhVVHRYUjFGTUtyR0g5a2wxbU5DcDRpalJqRWk1VE1hMGlibEhJNXZBR3RURE53Z1hpOEtNbEs0c05YQ011bE1YbHF6RlZlS01Dcm5pS2g1RUVyRTlqSVB2dXdVVGprV295WUd1X2cwTXkyVnExLWtEN2VnenhRIiwiZHAiOiJnNjJsZWhaM1RpTmJ2NDVzQnV3cTNlMUk3VDdlZ2VLTFdXNmpmWW50c2NsUGlzNXowbVpsVXNQTGtwaFpKMUtyVWx1ZkM4M2xodEdHVjNkVW40ZXBZbW53dndlZTNPSEhwZTZsU2c4UzB0dzFJU05QY2VzaC1DTUVYUjFjdnVsUUp5TGNKSXBBNzFLNWhaM2Vkcm1CNUx5LUdOVFIxTHZJbHBPM0EzYnRzRGsiLCJkcSI6Imtkdk5jalVfbTJPMzBzY05CR2N0TWd4cWFEUG83X3luRDNPcEFkek1PZHNQNi1SRGxHbXV5ZWZ4Yk5obU9PV3FRN29pdzBHQXk1TTdxUk5sVTgyTkxyOUp1bEYzUV9ScHFVamt4SFk2clkyZTdNekhrMHowUmZ0Sk45TUIwZkxndlhydnNWUktoMEIxMG5vekE3MGpITFo4UkYzaVNCWGV6M3M4V29hQjBMMCIsImUiOiJBUUFCIiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbImRlY3J5cHQiXSwia3R5IjoiUlNBIiwibiI6IjNlM3VYcDg2dDJjbm15cWNkby1kQUFsTGNrRTZxdlNsbmQ5UVg1SHYzcVQyQXp2V3lyd1RZLUprTEtEejkxakJkWE9ha1duLWJjWWk3UWs3YkZLcmNlRkpsUTZwVzNaSHh2bGhoSlBoelFPZDNaWW1qdi0wN2lETlM0NEx5MUd4dDllNEhLSG01OXFtc2kzaGZQS3VobnpPX0ZKcXJxM1ZmTHVYU21aSXN1YThKWnlKYnlWYXV0cWpScEg4MWM2TXJKMUNBd3FwZXl0SzVtMm5MaDh1VkowbDJqUXF5RmNoSXN6bzExSEJiYWttVW1QbjFYendoM1ZyOHZuTkNNeFpNMEE1VEswQlVqOVQ2ZXB3UmprVjI3MkVLMGFiR0ZveXN3R0FIUEN6Tm5HLUtKOXBDZG9aY1FsT0xveUdfaWZ2aTZtTmFOaUhIQnd6T3EtNnJMX2FIdyIsInAiOiItaFRIMHhvMmRPLTVDbTZJbWNZSG5MWURkZ05aOHNYb0s5LVNwczlFNXN5VmxzS1hfM3Q0X1pyTVltM1NtSTNjMV9Zb2x4UW9vUl9SeGxyenk2Q0QxQnRTNHpCaUU4U1FfSVAwcTI1VjVFYnI1QXpTMkVrSERwdG9iTDFHdnRtLUw0OV8zS3o3ZUxaaVp3WktvcDFsbnhMZE84R0dsWm1hbDBDR0RfTVNFTHMiLCJxIjoiNHk2VTQ4ZTRtZF9pSjQxRy1zeWVFbXVVNEEzdFpPMG0zQlB2S3lRY0RUWFdNaXVrM1ZLRGVYeEFUU2hEenhWUjBqYXZ6VThjbFdCbzZuTlZGTDc1SlNKUG9FZkF6cU5MWXRQQU1zaW85MEpOR1o1SG5ETXRQYWpWcEsza283MDJqdU9LS2tLTF9mTVltb2t1U3gxeU1QWldua0tXa1pmU1ZEUTVpclFfeC0wIiwicWkiOiJyRldoS2gyRWFEdElzV3dvRWlidmhTb21VVkZnTVd6bEF1c2pSVWYwR1JYaDBLRVJEclJ1RHFIZVZqZDZuSmRjV244eTVJbUhDSkJielltYjlRRlAwU0Y1dTR6TUttU1Awbm94MWFGbU5LTTVWel9FcE5nR1RZQTNEemtPcHQtV0tScEtNUGpMU2lKaXg2bTMtUWZhWTdWM0NKQWZRaVp0ZTZEUjdjYkhDOWMifQ==", 
        "eyJhbGciOiJQUzI1NiIsImUiOiJBUUFCIiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJSU0EiLCJuIjoibkZNNnZ4VjBRQzl3V25OZ09pd254a2FiSGNQZUVkaDZxN2NyTThOX3hiSlRuYnJtSDRfOFNpYi1lT0R1ZnBEaVI0TGRYVTh1UFAyMHhFdThPQ0lGYW1tNktudkVycVEzc2U0LVJmb05KSHM2aFNPM1Zjb1hBeGROanRJb3NNNldYc0ZnUWpZMjhacjY1ajZSX04yQ2hqYjdSWW5OTlVGX0FlQXFtNWd3WThtUE1GYVpKdHFpSi1SMlJMczhzUU81SWlUU3RnZnJNTVZFSzBSZjhPRTRheXRrLUhILVp1U0VWM0J0WGFXS3RXWW9qVjZpLVZtbFRJQU5hSElkZmZyUkFNMEE3UThTeU5PelZqWlZ4VWRSc05hbjdpdEtkYVIyVjRFckZSeXR2QTRBMWIzdnBEVU01M21WZXkwS1hQWUFCVlhxeVFQTlRiYTlmcWJ3aVRMajJRIn0=",
        "eyJhbGciOiJQUzI1NiIsImQiOiJPeUJ2MDk1MWZlRnppWUtpSHQ2Y25LNFA5WTRqN0hRSTBmSVI4UjQ4c2JYbFVuOWlrd1dPMHkwMGl0dm8yUTVMeC1pRGVjdDlIYXlJTnNhLWhpeTRCNnU5c2x2bDVIaFFhSWhJSFllYWVQWHpDSENkNDJEd20wYXhHeGY2TkFXdmNsLUozUUZNZnMyem9HcUNKVFpUTEJpWHFaR1pnRThwanJnTzVaTUdtbmNHd2RmVjkyaW0yVlhUcnpLVDJYa0RzeWp3bHByTm9rRnNmaFJFOF84TWpBemZjUkd6REMzam1jcl9fNXplVk9HNkxPMk9aYVVGRmlJamxJTnZOX0d1VVhVcGFuaG9LdzJKNFFjbGxkM3JWZmt1MWRnN1dvZ0VwZmNQNHRRUEU5WmgxZUs1VTdZUUlSY1dxNzZpbHNkSHJZdE8wa0FOOWtxUnpqUjlXOTJBMFEiLCJkcCI6Imc0U2Vudjd1eFl5VWtxZkwzUU9ONGszdklHMTFCQktZSV9BM2x5Nks1LXlOVVNsWHUtRF9lM29FWXF1N0VDUEdkUTZ5bjVHNzVqRkhQMXExLVFIX3cyR0VyZUIzWWlHRERvSHczZE90MEItaGhtRjduVlZXdjYzNjk5S2diOWhkUHRiU1V5VDRxSi1uZ1FKaXBkYWVjNXd3U0ZBZVVYdkc5LXowNGRRdmcycyIsImRxIjoiQThFaFUzNFFLR01yQThUekFYZEpadkRoaC1CdmViOGhfaG9mcVJCVHR1OVB4MFJaVm5XUlg5M2UtYWF4VFAxVzdoZlgweTBzRnRhN010MVBEOXg5ZWpFZkc1OFc2dFJwVnNqdG95X0RUR3VxZmlMQXEyemwtc0pNU1JCODQ4WHltTXFhN19Yc3hyZVZ0VTFaRnlteHlHZjg5ckxobTJaanNSOHJYMEJzT1RNIiwiZSI6IkFRQUIiLCJleHQiOnRydWUsImtleV9vcHMiOlsic2lnbiJdLCJrdHkiOiJSU0EiLCJuIjoibkZNNnZ4VjBRQzl3V25OZ09pd254a2FiSGNQZUVkaDZxN2NyTThOX3hiSlRuYnJtSDRfOFNpYi1lT0R1ZnBEaVI0TGRYVTh1UFAyMHhFdThPQ0lGYW1tNktudkVycVEzc2U0LVJmb05KSHM2aFNPM1Zjb1hBeGROanRJb3NNNldYc0ZnUWpZMjhacjY1ajZSX04yQ2hqYjdSWW5OTlVGX0FlQXFtNWd3WThtUE1GYVpKdHFpSi1SMlJMczhzUU81SWlUU3RnZnJNTVZFSzBSZjhPRTRheXRrLUhILVp1U0VWM0J0WGFXS3RXWW9qVjZpLVZtbFRJQU5hSElkZmZyUkFNMEE3UThTeU5PelZqWlZ4VWRSc05hbjdpdEtkYVIyVjRFckZSeXR2QTRBMWIzdnBEVU01M21WZXkwS1hQWUFCVlhxeVFQTlRiYTlmcWJ3aVRMajJRIiwicCI6InpiN2NFbjBURmtVYUM3TEdXWGlLaF9iZDhsb2VaNDBrZ01zbER2RVZoTjByZlNXdzJSdnotaEhJRngtLWQ0aFJRUjRoWkIyU3M2RFRycVAyQm9PU0E1QjNSM3d2ZGMydzNYeDBlSFdrbmlnUGI1dVpkQlNoYmVVa0R3U1VIZG1lVzA3ZDlfMlVNX0dhalcyRm1oZDZ2OGtUVHA0elRjd1ktcW93M2VieEVhTSIsInEiOiJ3b0lrSmV3WXg4NkFGcWlIckVjQmRuSFVDVTFna1cwR2hmNVZQSUdzNE5jUUdyMGpMSUNzdGZ0UVBxci1oT0tqemwtQXRsWVB5WWFWckZJbDRMNkFDVzRtbWRlaWZPNEY2SlE0cl9FZlo1dG5YeW9OekJyX1V0Tjh1X1VRQ2ttODlsTzZHQTNwRDBBODVCV0g1UXFES0RuQU1JbXNyZ252VG4zNW1feW41Rk0iLCJxaSI6IlNudU5hM0t0aWltMWRwQ3hEV1ZBOThxYkhwZkZ6VzJZRnBNREdSdjFxcDFvc0xqN1BVNFN1bTVmQlZNYzBuSFEyOEJrTWttdXVOOGV3Y2ktY1dVNFFnMGJJRjRsb2dubzQxLXhWY2VNWDhWcFVWTFZJeWRFc1ZFSk43eDdCcENtWkM3UDJGZEVPeUF1THBKcVdFTWxhWFAzdENrbEFIRXNHZnlsbVFxWktlWSJ9"
      );
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
});
