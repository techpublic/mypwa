/**
 * VaultPGP Crypto Worker v0.2
 * Handles all heavy OpenPGP operations off the main thread:
 *   generateKey, encrypt (always signs), decrypt (always verifies)
 * openpgp.min.js is loaded locally — no external requests.
 */
importScripts('./openpgp.min.js');

self.onmessage = async function (event) {
  const { id, action, params } = event.data;
  try {
    let data;
    switch (action) {

      /* ── Key Generation ─────────────────────────── */
      case 'generateKey': {
        const opts = {
          userIDs: [{ name: params.name, email: params.email }],
          format: 'armored'
        };
        if (params.keyType === 'rsa4096') {
          opts.type = 'rsa';
          opts.rsaBits = 4096;
        } else {
          opts.type = 'curve25519'; // Ed25519 (signing) + X25519 (encryption)
        }
        const { privateKey, publicKey } = await openpgp.generateKey(opts);
        data = { privateKey, publicKey };
        break;
      }

      /* ── Encrypt + Sign ─────────────────────────── */
      case 'encrypt': {
        /*
         * params:
         *   plaintext            string
         *   recipientArmoredKeys string[]  (public keys of recipients)
         *   signingArmoredKey    string    (AES-unlocked private key, armored)
         */
        const encryptionKeys = await Promise.all(
          params.recipientArmoredKeys.map(k => openpgp.readKey({ armoredKey: k }))
        );
        const signingKeys = await openpgp.readPrivateKey({
          armoredKey: params.signingArmoredKey
        });
        const message = await openpgp.createMessage({ text: params.plaintext });
        data = await openpgp.encrypt({
          message,
          encryptionKeys,
          signingKeys,
          config: { preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256 }
        });
        break;
      }

      /* ── Decrypt + Verify ───────────────────────── */
      case 'decrypt': {
        /*
         * params:
         *   armoredMessage          string
         *   decryptionArmoredKey    string    (AES-unlocked private key, armored)
         *   verificationArmoredKeys string[]  (all public keys from keyring)
         *   verificationKeyMeta     {fingerprint, name, email}[] (parallel array)
         */
        const decryptionKeys = await openpgp.readPrivateKey({
          armoredKey: params.decryptionArmoredKey
        });
        const message = await openpgp.readMessage({ armoredMessage: params.armoredMessage });

        const verificationKeys = await Promise.all(
          params.verificationArmoredKeys.map(k => openpgp.readKey({ armoredKey: k }))
        );

        const decryptOpts = { message, decryptionKeys };
        if (verificationKeys.length > 0) decryptOpts.verificationKeys = verificationKeys;

        const { data: plaintext, signatures } = await openpgp.decrypt(decryptOpts);

        // Determine signature status
        let sigStatus   = 'unsigned'; // 'valid' | 'invalid' | 'unsigned' | 'unknown_key'
        let signerKeyId = null;
        let signerName  = null;
        let signerEmail = null;

        if (signatures && signatures.length > 0) {
          const sig = signatures[0];
          signerKeyId = sig.keyID.toHex().toUpperCase();

          try {
            await sig.verified; // resolves = valid, rejects = bad
            sigStatus = 'valid';
            // Find signer info from parallel meta array by matching key ID suffix
            const meta = params.verificationKeyMeta.find(m =>
              m.fingerprint.toUpperCase().endsWith(signerKeyId)
            );
            if (meta) { signerName = meta.name; signerEmail = meta.email; }
          } catch (verifyErr) {
            const msg = verifyErr.message || '';
            const isKeyMissing =
              msg.includes('Could not find') ||
              msg.includes('not found') ||
              msg.includes('No matching') ||
              verificationKeys.length === 0;
            sigStatus = isKeyMissing ? 'unknown_key' : 'invalid';
          }
        }

        data = { plaintext, sigStatus, signerKeyId, signerName, signerEmail };
        break;
      }

      default:
        throw new Error('Unknown worker action: ' + action);
    }

    self.postMessage({ id, success: true, data });
  } catch (err) {
    self.postMessage({ id, success: false, error: err.message });
  }
};
