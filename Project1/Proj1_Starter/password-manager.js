"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      salt: undefined,
      kvs: {},
      auth: undefined,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      macKey: undefined,
      encKey: undefined,
    };
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    // Generate random salt for PBKDF2
    const salt = getRandomBytes(16);

    // Derive key material from password and salt (single PBKDF2 call)
    const baseKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      512
    ); // 512 bits = 64 bytes

    const derivedBytes = new Uint8Array(derivedBits);
    const macKeyBytes = derivedBytes.slice(0, 32);  // for HMAC-SHA-256
    const encKeyBytes = derivedBytes.slice(32);     // for AES-GCM

    const macKey = await subtle.importKey(
      "raw",
      macKeyBytes,
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign", "verify"]
    );

    const encKey = await subtle.importKey(
      "raw",
      encKeyBytes,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    const kc = new Keychain();

    // Public / serializable data
    kc.data.salt = encodeBuffer(salt);
    kc.data.kvs = {};

    // Secret keys (never serialized)
    kc.secrets.macKey = macKey;
    kc.secrets.encKey = encKey;

    // Create an authentication record to verify password correctness on load.
    const authIv = getRandomBytes(12);
    const authPlain = stringToBuffer("auth");
    const authCipher = await subtle.encrypt(
      { name: "AES-GCM", iv: authIv },
      encKey,
      authPlain
    );
    kc.data.auth = {
      iv: encodeBuffer(authIv),
      ciphertext: encodeBuffer(authCipher),
    };

    return kc;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // Verify integrity using trustedDataCheck, if provided (rollback protection)
    if (trustedDataCheck !== undefined) {
      const computedHashBuf = await subtle.digest(
        "SHA-256",
        stringToBuffer(repr)
      );
      const computedHash = encodeBuffer(computedHashBuf);
      if (computedHash !== trustedDataCheck) {
        throw "Integrity check failed";
      }
    }

    const obj = JSON.parse(repr);

    // Recreate salt
    const salt = decodeBuffer(obj.salt);

    // Derive keys from provided password and stored salt (single PBKDF2 call)
    const baseKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const derivedBits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      baseKey,
      512
    );

    const derivedBytes = new Uint8Array(derivedBits);
    const macKeyBytes = derivedBytes.slice(0, 32);
    const encKeyBytes = derivedBytes.slice(32);

    const macKey = await subtle.importKey(
      "raw",
      macKeyBytes,
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign", "verify"]
    );

    const encKey = await subtle.importKey(
      "raw",
      encKeyBytes,
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );

    const kc = new Keychain();
    kc.data.salt = obj.salt;
    kc.data.kvs = obj.kvs || {};
    kc.data.auth = obj.auth;
    kc.secrets.macKey = macKey;
    kc.secrets.encKey = encKey;

    // Verify password correctness and detect tampering via auth record
    if (!kc.data.auth || !kc.data.auth.iv || !kc.data.auth.ciphertext) {
      throw "Missing authentication record";
    }

    try {
      const authIv = decodeBuffer(kc.data.auth.iv);
      const authCipher = decodeBuffer(kc.data.auth.ciphertext);
      const authPlainBuf = await subtle.decrypt(
        { name: "AES-GCM", iv: authIv },
        encKey,
        authCipher
      );
      const authPlain = bufferToString(authPlainBuf);
      if (authPlain !== "auth") {
        throw "Invalid authentication value";
      }
    } catch (e) {
      // Wrong password or tampered data
      throw "Invalid password or corrupted data";
    }

    return kc;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // Serialize only public data
    const contents = JSON.stringify({
      salt: this.data.salt,
      kvs: this.data.kvs,
      auth: this.data.auth,
    });

    const hashBuf = await subtle.digest(
      "SHA-256",
      stringToBuffer(contents)
    );
    const checksum = encodeBuffer(hashBuf);

    return [contents, checksum];
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Compute HMAC of domain name to use as key in kvs (swap-attack resistant)
    const tagBuf = await subtle.sign(
      { name: "HMAC" },
      this.secrets.macKey,
      stringToBuffer(name)
    );
    const tag = encodeBuffer(tagBuf);

    const record = this.data.kvs[tag];
    if (!record) {
      return null;
    }

    try {
      const iv = decodeBuffer(record.iv);
      const ciphertext = decodeBuffer(record.ciphertext);
      const plaintextBuf = await subtle.decrypt(
        { name: "AES-GCM", iv },
        this.secrets.encKey,
        ciphertext
      );
      const plaintextStr = bufferToString(plaintextBuf);
      const obj = JSON.parse(plaintextStr);

      // Explicitly check that the embedded domain matches the requested one
      if (obj.domain !== name) {
        throw "Swap attack detected";
      }

      // Remove padding to hide real password length
      const paddedPw = obj.password;
      const pw = paddedPw.replace(/\0+$/g, "");
      return pw;
    } catch (e) {
      // Any failure here indicates tampering
      throw "Decryption or integrity check failed";
    }
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // Pad password to fixed length to hide length information
    if (value.length > MAX_PASSWORD_LENGTH) {
      throw "Password too long";
    }
    let paddedPw = value;
    if (paddedPw.length < MAX_PASSWORD_LENGTH) {
      paddedPw = paddedPw + "\0".repeat(MAX_PASSWORD_LENGTH - paddedPw.length);
    }

    const tagBuf = await subtle.sign(
      { name: "HMAC" },
      this.secrets.macKey,
      stringToBuffer(name)
    );
    const tag = encodeBuffer(tagBuf);

    const recordObj = {
      domain: name,
      password: paddedPw,
    };
    const plaintext = stringToBuffer(JSON.stringify(recordObj));

    const iv = getRandomBytes(12);
    const ciphertext = await subtle.encrypt(
      { name: "AES-GCM", iv },
      this.secrets.encKey,
      plaintext
    );

    this.data.kvs[tag] = {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(ciphertext),
    };
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    const tagBuf = await subtle.sign(
      { name: "HMAC" },
      this.secrets.macKey,
      stringToBuffer(name)
    );
    const tag = encodeBuffer(tagBuf);

    if (Object.prototype.hasOwnProperty.call(this.data.kvs, tag)) {
      delete this.data.kvs[tag];
      return true;
    }
    return false;
  };
};

module.exports = { Keychain }
