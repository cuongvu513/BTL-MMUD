'use strict'

/** ******* Imports ********/

const crypto = require('crypto')

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    // Generate ElGamal keypair for this user
    this.EGKeyPair = await generateEG()
    
    // Create certificate with username and public key
    const certificate = {
      username: username,
      publicKey: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }
    
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    
    // Verify the certificate signature using the CA's public key
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!valid) {
      throw new Error('Invalid certificate signature')
    }
    
    // Import the public key from JSON format
    const publicKey = await crypto.webcrypto.subtle.importKey(
      'jwk',
      certificate.publicKey,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
    
    // Store the certificate with the imported public key
    this.certs[certificate.username] = {
      username: certificate.username,
      publicKey: publicKey
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    // Initialize connection if it doesn't exist
    if (!this.conns[name]) {
      this.conns[name] = {
        DHs: this.EGKeyPair, // sender's DH ratchet keypair (use our main keypair)
        DHr: null, // receiver's DH ratchet public key
        RK: null, // root key
        CKs: null, // sending chain key
        CKr: null, // receiving chain key
        Ns: 0, // sending message number
        Nr: 0, // receiving message number
        PN: 0, // previous sending chain length
        receivedMessages: new Set() // for replay detection
      }
    }
    
    const conn = this.conns[name]
    const receiverCert = this.certs[name]
    
    // Generate ephemeral keypair for this message
    const ephemeralKeyPair = await generateEG()
    
    // Determine which receiver public key to use
    let receiverPubKey
    if (conn.DHr) {
      // If we have receiver's DH ratchet key from a previous message, use it
      receiverPubKey = conn.DHr
    } else {
      // First message: use receiver's certificate public key
      receiverPubKey = receiverCert.publicKey
    }
    
    // Perform DH with receiver's public key
    const sharedSecret = await computeDH(ephemeralKeyPair.sec, receiverPubKey)
    
    // Derive message key from shared secret
    const messageKey = await HMACtoAESKey(sharedSecret, `msg-${conn.Ns}`)
    
    // Generate IV for receiver
    const receiverIV = genRandomSalt(16)
    
    // Create header
    const header = {
      vGov: null,
      cGov: null,
      ivGov: null,
      receiverIV: receiverIV,
      ephemeralPub: await cryptoKeyToJSON(ephemeralKeyPair.pub),
      senderPub: await cryptoKeyToJSON(conn.DHs.pub),
      messageNum: conn.Ns,
      prevChainLen: conn.PN
    }
    
    // Encrypt for government
    const govEphemeral = await generateEG()
    const govSharedSecret = await computeDH(govEphemeral.sec, this.govPublicKey)
    const govKey = await HMACtoAESKey(govSharedSecret, govEncryptionDataStr)
    const govIV = genRandomSalt(16)
    
    // Export message key as ArrayBuffer for government encryption
    const messageKeyBuffer = await HMACtoAESKey(sharedSecret, `msg-${conn.Ns}`, true)
    const cGov = await encryptWithGCM(govKey, messageKeyBuffer, govIV)
    
    header.vGov = await cryptoKeyToJSON(govEphemeral.pub)
    header.cGov = cGov
    header.ivGov = govIV
    
    // Import vGov back to CryptoKey for header
    header.vGov = await crypto.webcrypto.subtle.importKey(
      'jwk',
      header.vGov,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
    
    // Encrypt the plaintext with authenticated data
    const ciphertext = await encryptWithGCM(messageKey, plaintext, receiverIV, JSON.stringify(header))
    
    // Update sending message number
    conn.Ns++
    
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    // Initialize connection if it doesn't exist
    if (!this.conns[name]) {
      this.conns[name] = {
        DHs: this.EGKeyPair, // our main keypair
        DHr: null,
        RK: null,
        CKs: null,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        receivedMessages: new Set()
      }
    }
    
    const conn = this.conns[name]
    
    // Replay attack detection
    const messageId = `${header.messageNum}-${header.prevChainLen}`
    if (conn.receivedMessages.has(messageId)) {
      throw new Error('Replay attack detected')
    }
    
    // Import ephemeral public key from header
    const ephemeralPub = await crypto.webcrypto.subtle.importKey(
      'jwk',
      header.ephemeralPub,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
    
    // Import sender's public key from header and update DHr
    conn.DHr = await crypto.webcrypto.subtle.importKey(
      'jwk',
      header.senderPub,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
    
    // Perform DH with our private key and sender's ephemeral public key
    const sharedSecret = await computeDH(this.EGKeyPair.sec, ephemeralPub)
    
    // Derive message key (use the same counter as sender)
    const messageKey = await HMACtoAESKey(sharedSecret, `msg-${header.messageNum}`)
    
    // Decrypt the message
    let plaintext
    try {
      const decrypted = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, JSON.stringify(header))
      plaintext = bufferToString(decrypted)
    } catch (e) {
      throw new Error('Decryption failed - message may be tampered or not intended for this recipient')
    }
    
    // Mark message as received
    conn.receivedMessages.add(messageId)
    
    // Update receiving message number
    if (header.messageNum >= conn.Nr) {
      conn.Nr = header.messageNum + 1
    }
    
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
