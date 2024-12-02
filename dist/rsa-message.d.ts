declare class MDPGP {
  init(): Promise<string>;
  setPublicKey(userId: string, publicKey: string): void;
  encryptMessage(message: string, userId: string): Promise<string>;
  decryptMessage(encryptedMessage: string, userId: string): Promise<string>;
}

export default MDPGP;