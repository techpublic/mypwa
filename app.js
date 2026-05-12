/**
 * PGPhone v0.3 — Secure Offline PGP PWA
 *
 * v0.3 changes:
 *  - Mandatory first-time setup: app locked until first key pair is generated
 *  - Password reveal fixed: direct binding via bindRevealToggles() helper
 *  - Name: VaultPGP → PGPhone
 *
 * Security architecture (unchanged):
 *  - openpgp.js v6  (Ed25519 / RSA-4096)
 *  - Web Crypto PBKDF2 → AES-256-GCM  (private key at rest)
 *  - IndexedDB  (all persistent data)
 *  - Passphrases are NEVER stored or persisted
 *  - All heavy PGP operations run in a Web Worker
 */

'use strict';

/* ════════════════════════════════════════════════
   1. SERVICE WORKER REGISTRATION
   ════════════════════════════════════════════════ */
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js')
    .then(reg => console.log('[PGPhone] SW registered, scope:', reg.scope))
    .catch(err => console.warn('[PGPhone] SW registration failed:', err));
}

/* ════════════════════════════════════════════════
   2. DATABASE MODULE  (IndexedDB — unchanged)
   ════════════════════════════════════════════════ */
const DB = (() => {
  const DB_NAME    = 'vaultpgp';   // keep existing DB name so stored keys survive upgrade
  const DB_VERSION = 1;
  const STORE      = 'keys';
  let _db = null;

  function open() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains(STORE)) {
          const store = db.createObjectStore(STORE, { keyPath: 'id' });
          store.createIndex('fingerprint', 'fingerprint', { unique: false });
        }
      };
      req.onsuccess = e => { _db = e.target.result; resolve(_db); };
      req.onerror   = e => reject(e.target.error);
    });
  }

  async function tx(mode) {
    const db = await open();
    return db.transaction(STORE, mode).objectStore(STORE);
  }

  function wrap(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }

  return {
    async put(record)  { return wrap((await tx('readwrite')).put(record)); },
    async get(id)      { return wrap((await tx('readonly')).get(id)); },
    async getAll()     { return wrap((await tx('readonly')).getAll()); },
    async delete(id)   { return wrap((await tx('readwrite')).delete(id)); }
  };
})();

/* ════════════════════════════════════════════════
   3. CRYPTO MODULE  (Web Crypto — unchanged)
   ════════════════════════════════════════════════ */
const Crypto = (() => {
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();

  async function deriveKey(passphrase, salt) {
    const raw = await crypto.subtle.importKey(
      'raw', ENC.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 310_000, hash: 'SHA-256' },
      raw,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  return {
    async encryptPrivateKey(armoredPrivateKey, passphrase) {
      const salt    = crypto.getRandomValues(new Uint8Array(32));
      const iv      = crypto.getRandomValues(new Uint8Array(12));
      const aesKey  = await deriveKey(passphrase, salt);
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, aesKey, ENC.encode(armoredPrivateKey)
      );
      return { encryptedPrivateKey: encrypted, salt, iv };
    },

    async decryptPrivateKey(encryptedPrivateKey, salt, iv, passphrase) {
      const aesKey   = await deriveKey(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, aesKey, encryptedPrivateKey
      );
      return DEC.decode(decrypted);
    }
  };
})();

/* ════════════════════════════════════════════════
   4. CRYPTO WORKER BRIDGE  (unchanged)
   ════════════════════════════════════════════════ */
const CryptoWorker = (() => {
  let worker    = null;
  const pending = new Map();
  let idCounter = 0;

  function getWorker() {
    if (worker) return worker;
    worker = new Worker('./worker.js');
    worker.onmessage = e => {
      const { id, success, data, error } = e.data;
      const cb = pending.get(id);
      if (!cb) return;
      pending.delete(id);
      success ? cb.resolve(data) : cb.reject(new Error(error));
    };
    worker.onerror = e => {
      console.error('[CryptoWorker]', e);
      pending.forEach(cb => cb.reject(new Error('Worker error: ' + (e.message || 'unknown'))));
      pending.clear();
      worker = null;
    };
    return worker;
  }

  function call(action, params) {
    return new Promise((resolve, reject) => {
      const id = ++idCounter;
      pending.set(id, { resolve, reject });
      getWorker().postMessage({ id, action, params });
    });
  }

  return {
    generateKey: p => call('generateKey', p),
    encrypt:     p => call('encrypt', p),
    decrypt:     p => call('decrypt', p)
  };
})();

/* ════════════════════════════════════════════════
   5. PGP MODULE  (unchanged)
   ════════════════════════════════════════════════ */
const PGP = (() => {

  async function unlockPrivateKey(record, passphrase) {
    if (!record.hasPrivate)
      throw new Error('This key has no private key stored on this device.');
    return Crypto.decryptPrivateKey(
      record.encryptedPrivateKey, record.salt, record.iv, passphrase
    );
  }

  return {
    async encrypt(plaintext, recipientRecords, signingRecord, passphrase) {
      const signingArmoredKey = await unlockPrivateKey(signingRecord, passphrase);
      return CryptoWorker.encrypt({
        plaintext,
        recipientArmoredKeys: recipientRecords.map(r => r.publicKeyArmored),
        signingArmoredKey
      });
    },

    async decrypt(armoredMessage, decryptRecord, passphrase, allKeys) {
      const decryptionArmoredKey    = await unlockPrivateKey(decryptRecord, passphrase);
      const verificationArmoredKeys = allKeys.map(k => k.publicKeyArmored);
      const verificationKeyMeta     = allKeys.map(k => ({
        fingerprint: k.fingerprint, name: k.name, email: k.email
      }));
      return CryptoWorker.decrypt({
        armoredMessage, decryptionArmoredKey,
        verificationArmoredKeys, verificationKeyMeta
      });
    },

    async inspectKey(armoredKey) {
      let key;
      try { key = await openpgp.readKey({ armoredKey }); }
      catch { key = await openpgp.readPrivateKey({ armoredKey }); }
      const uid = key.users[0]?.userID;
      return {
        name:        uid?.name  || 'Unknown',
        email:       uid?.email || '',
        fingerprint: key.getFingerprint().toUpperCase(),
        keyId:       key.getKeyID().toHex().toUpperCase(),
        keyType:     key.getAlgorithmInfo().algorithm,
        isPrivate:   key.isPrivate()
      };
    }
  };
})();

/* ════════════════════════════════════════════════
   6. UI UTILITIES
   ════════════════════════════════════════════════ */
const UI = (() => ({

  toast(message, type = 'info', duration = 3200) {
    const container = document.getElementById('toast-container');
    // Dismiss any existing toast immediately before showing the new one
    const existing = container.querySelector('.toast');
    if (existing) {
      existing.classList.add('out');
      setTimeout(() => existing.remove(), 220);
    }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    // Animate in (slight delay lets browser paint the initial off-screen state)
    requestAnimationFrame(() => {
      requestAnimationFrame(() => el.classList.add('in'));
    });
    const hide = () => {
      el.classList.remove('in');
      el.classList.add('out');
      setTimeout(() => { if (el.parentNode) el.remove(); }, 320);
    };
    el._hideTimer = setTimeout(hide, duration);
    // Tap to dismiss
    el.addEventListener('click', () => {
      clearTimeout(el._hideTimer);
      hide();
    });
  },

  showLoading(text = 'Working…') {
    document.getElementById('loadingText').textContent = text;
    document.getElementById('loadingOverlay').classList.add('visible');
  },

  hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('visible');
  },

  openModal(bodyHTML, onOpen) {
    document.getElementById('modalBody').innerHTML = bodyHTML;
    document.getElementById('modalOverlay').classList.add('visible');
    // Bind reveal toggles for any password fields in the freshly injected HTML
    bindRevealToggles(document.getElementById('modalBody'));
    if (onOpen) onOpen();
  },

  closeModal() {
    // Guarded — cannot dismiss during mandatory onboarding
    if (App._onboarding) return;
    document.getElementById('modalOverlay').classList.remove('visible');
  },

  copyText(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      if (btn) {
        btn.textContent = '✓ Copied';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.innerHTML = copyIconHTML() + ' Copy';
          btn.classList.remove('copied');
        }, 2000);
      }
    }).catch(() => UI.toast('Copy failed — select text manually.', 'error'));
  },

  formatFingerprint(fp) { return fp.match(/.{1,4}/g)?.join(' ') || fp; },
  initial(name)         { return name ? name.trim()[0].toUpperCase() : '?'; }

}))();

/* ════════════════════════════════════════════════
   7. PASSWORD REVEAL HELPER
   Direct binding — more reliable on iOS Safari
   than document-level event delegation.

   Root cause of prior bug: when the SVG child is
   the event target, e.target differs from the
   button element that holds data-target. Using
   e.currentTarget (set by addEventListener on the
   button itself) always resolves to the button.
   Also: pointer-events:none on SVG children
   prevents SVG paths from stealing touch events.
   ════════════════════════════════════════════════ */
function bindRevealToggles(root) {
  const container = root || document;
  container.querySelectorAll('.input-reveal').forEach(btn => {
    btn.removeEventListener('click', _onRevealClick);
    btn.addEventListener('click', _onRevealClick);
    // Auto-hide when the associated input loses focus
    const target = document.getElementById(btn.dataset.target);
    if (target) {
      target.removeEventListener('blur', _onRevealInputBlur);
      target.addEventListener('blur', _onRevealInputBlur);
    }
  });
}

function _onRevealInputBlur(e) {
  e.currentTarget.type = 'password';
}

function _onRevealClick(e) {
  e.preventDefault();
  e.stopPropagation();
  // e.currentTarget is always the button itself, regardless of which child was tapped
  const btn    = e.currentTarget;
  const target = document.getElementById(btn.dataset.target);
  if (!target) return;
  target.type = (target.type === 'password') ? 'text' : 'password';
  // Update aria label
  btn.setAttribute('aria-label', target.type === 'text' ? 'Hide passphrase' : 'Show passphrase');
}

/* ════════════════════════════════════════════════
   8. KEYS TAB
   ════════════════════════════════════════════════ */
const KeysTab = (() => {

  function renderKey(record) {
    const isContact  = !record.hasPrivate;
    const algoLabel  = record.keyType && record.keyType.includes('rsa') ? 'RSA-4096' : 'Ed25519';
    const badgeClass = isContact ? 'badge-pub-only' : 'badge-type';
    const isDefault  = !!record.isDefault;

    return `
      <div class="key-card${isContact ? ' public-only' : ''}" data-id="${record.id}">
        <div class="key-card-header" data-expand="${record.id}">
          <div class="key-avatar">${UI.initial(record.name)}</div>
          <div class="key-info">
            <div class="key-name">${escHtml(record.name)}</div>
            <div class="key-email">${escHtml(record.email)}</div>
          </div>
          <div class="key-card-badges">
            <button class="bookmark-btn${isDefault ? ' active' : ''}"
              data-action="toggleDefault" data-id="${record.id}"
              type="button" aria-label="${isDefault ? 'Remove default' : 'Set as default'}">
              <svg width="14" height="16" viewBox="0 0 14 16" fill="${isDefault ? 'currentColor' : 'none'}" xmlns="http://www.w3.org/2000/svg">
                <path d="M2 2.5A1.5 1.5 0 0 1 3.5 1h7A1.5 1.5 0 0 1 12 2.5v12l-5-3-5 3V2.5z"
                  stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
              </svg>
            </button>
            <span class="badge ${badgeClass}">${algoLabel}</span>
          </div>
        </div>
        <div class="key-expand" id="expand-${record.id}">
          <div class="key-expand-inner">
            <div class="key-fingerprint">${UI.formatFingerprint(record.fingerprint)}</div>
            <div class="key-actions">
              <button class="btn btn-ghost btn-sm" data-action="exportPub" data-id="${record.id}">Export Public</button>
              ${record.hasPrivate
                ? `<button class="btn btn-ghost btn-sm" data-action="exportPriv" data-id="${record.id}">Export Private</button>`
                : ''}
              <button class="btn btn-danger btn-sm" data-action="deleteKey" data-id="${record.id}">Delete</button>
            </div>
          </div>
        </div>
      </div>`;
  }

  function renderSection(title, subtitle, iconChar, sectionClass, keys, emptyMsg) {
    return `
      <div class="keys-section ${sectionClass}">
        <div class="keys-section-header">
          <div class="keys-section-icon">${iconChar}</div>
          <div>
            <div class="keys-section-title">${title}</div>
            <div class="keys-section-sub">${subtitle}</div>
          </div>
          <span class="keys-section-count">${keys.length}</span>
        </div>
        <div class="keys-section-body">
          ${keys.length > 0
            ? keys.map(renderKey).join('')
            : `<div class="keys-section-empty">${emptyMsg}</div>`}
        </div>
      </div>`;
  }

  async function render() {
    const allKeys  = await DB.getAll();
    const myKeys   = allKeys.filter(k =>  k.hasPrivate).sort((a,b) => a.name.localeCompare(b.name));
    const contacts = allKeys.filter(k => !k.hasPrivate).sort((a,b) => a.name.localeCompare(b.name));
    const list     = document.getElementById('keysList');
    const badge    = document.getElementById('keyCount');

    if (allKeys.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🔑</div>
          <div class="empty-title">No keys yet</div>
          <div class="empty-subtitle">Generate your key pair to get started,<br>then import your contacts' public keys.</div>
        </div>`;
      badge.style.display = 'none';
    } else {
      list.innerHTML =
        renderSection(
          'My Keys', 'Your personal key pairs — keep private keys secret',
          '🔐', 'section-mine', myKeys,
          'No personal keys. Use "Generate" to create your key pair.'
        ) +
        renderSection(
          'Contacts', 'Public keys of people you communicate with',
          '👤', 'section-contacts', contacts,
          'No contacts yet. Import a contact\'s public key to encrypt messages for them.'
        );
      badge.textContent  = `${allKeys.length} key${allKeys.length !== 1 ? 's' : ''}`;
      badge.style.display = 'inline-block';
    }

    App.refreshKeySelectors(allKeys);
  }

  function bindEvents() {
    document.getElementById('keysList').addEventListener('click', async e => {
      const expandEl = e.target.closest('[data-expand]');
      const actionEl = e.target.closest('[data-action]');

      if (expandEl && !actionEl) {
        const id     = expandEl.dataset.expand;
        const panel  = document.getElementById(`expand-${id}`);
        const opening = !panel.classList.contains('open');
        document.querySelectorAll('.key-expand.open').forEach(o => o.classList.remove('open'));
        if (opening) panel.classList.add('open');
      }

      if (actionEl) {
        const { action: act, id } = actionEl.dataset;
        const record = await DB.get(id);
        if (!record) return;
        if (act === 'exportPub')     showExportPublic(record);
        if (act === 'exportPriv')    showExportPrivate(record);
        if (act === 'deleteKey')     confirmDelete(record);
        if (act === 'toggleDefault') {
          const newDefault = !record.isDefault;
          // My keys: only one default allowed — clear others in the same group
          if (record.hasPrivate && newDefault) {
            const allKeys = await DB.getAll();
            for (const k of allKeys.filter(k => k.hasPrivate && k.isDefault && k.id !== id)) {
              await DB.put({ ...k, isDefault: false });
            }
          }
          await DB.put({ ...record, isDefault: newDefault });
          await render();
        }
      }
    });

    document.getElementById('btnGenerate').addEventListener('click', () => showGenerateModal(false));
    document.getElementById('btnImport').addEventListener('click', showImportModal);
  }

  /* ── First-time setup entry point ─────────────── */
  function showFirstTimeSetup() {
    showGenerateModal(true);
  }

  /* ── Generate modal ────────────────────────────── */
  function showGenerateModal(isFirstTime) {
    UI.openModal(`
      ${isFirstTime
        ? `<div class="onboarding-banner">
             <div class="onboarding-banner-icon">🔐</div>
             <div>
               <div class="onboarding-banner-title">Welcome to PGPhone</div>
               <div class="onboarding-banner-sub">Generate your personal key pair to get started. This is required to use the app.</div>
             </div>
           </div>`
        : `<h2 class="modal-title">Generate Key Pair</h2>`
      }
      <div class="form-group">
        <label class="form-label" for="genName">Your Name</label>
        <input type="text" class="form-input" id="genName" placeholder="Alice Smith" autocomplete="name">
      </div>
      <div class="form-group">
        <label class="form-label" for="genEmail">Email Address</label>
        <input type="email" class="form-input" id="genEmail" placeholder="alice@example.com" autocomplete="email">
      </div>
      <div class="form-group">
        <label class="form-label">Key Type</label>
        <div class="seg-control" id="genKeyTypeSeg">
          <button class="seg-btn active" data-val="curve25519">Ed25519 (Modern)</button>
          <button class="seg-btn" data-val="rsa4096">RSA-4096 (Classic)</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="genPass">Passphrase</label>
        <div class="input-group">
          <input type="password" class="form-input" id="genPass"
            placeholder="Strong passphrase" autocomplete="new-password">
          <button class="input-reveal" data-target="genPass" type="button" aria-label="Show passphrase">${revealIconHTML()}</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="genPassConfirm">Confirm Passphrase</label>
        <div class="input-group">
          <input type="password" class="form-input" id="genPassConfirm"
            placeholder="Re-enter passphrase" autocomplete="new-password">
          <button class="input-reveal" data-target="genPassConfirm" type="button" aria-label="Show passphrase">${revealIconHTML()}</button>
        </div>
      </div>
      <div class="info-panel warn">
        ⚠ Your passphrase is never stored. If you lose it, your private key cannot be recovered.
      </div>
      <div class="modal-actions">
        ${isFirstTime ? '' : '<button class="btn btn-ghost" id="genCancel">Cancel</button>'}
        <button class="btn btn-primary${isFirstTime ? ' btn-full' : ''}" id="genConfirm">
          ${isFirstTime ? 'Generate My Key Pair' : 'Generate'}
        </button>
      </div>
    `, () => {
      let keyType = 'curve25519';
      document.querySelectorAll('#genKeyTypeSeg .seg-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('#genKeyTypeSeg .seg-btn').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          keyType = btn.dataset.val;
        });
      });

      if (!isFirstTime) {
        document.getElementById('genCancel').addEventListener('click', UI.closeModal);
      }

      document.getElementById('genConfirm').addEventListener('click', async () => {
        const name  = document.getElementById('genName').value.trim();
        const email = document.getElementById('genEmail').value.trim();
        const pass  = document.getElementById('genPass').value;
        const conf  = document.getElementById('genPassConfirm').value;

        if (!name)           return UI.toast('Please enter your name.', 'error');
        if (!email)          return UI.toast('Please enter your email.', 'error');
        if (!pass)           return UI.toast('Please enter a passphrase.', 'error');
        if (pass.length < 8) return UI.toast('Passphrase must be at least 8 characters.', 'error');
        if (pass !== conf)   return UI.toast('Passphrases do not match.', 'error');

        // Don't close modal — hide behind loading overlay
        UI.showLoading(keyType === 'rsa4096'
          ? 'Generating RSA-4096 key… (10–30s)'
          : 'Generating Ed25519 key…');

        try {
          const { privateKey: armoredPriv, publicKey: armoredPub } =
            await CryptoWorker.generateKey({ name, email, keyType });

          const meta = await PGP.inspectKey(armoredPub);
          const { encryptedPrivateKey, salt, iv } =
            await Crypto.encryptPrivateKey(armoredPriv, pass);

          await DB.put({
            id: meta.fingerprint, name: meta.name, email: meta.email,
            keyType: meta.keyType, fingerprint: meta.fingerprint, keyId: meta.keyId,
            publicKeyArmored: armoredPub, encryptedPrivateKey, salt, iv,
            hasPrivate: true, createdAt: new Date().toISOString()
          });

          // Unlock the app on first-time success
          App._onboarding = false;

          UI.hideLoading();
          // Close modal now that onboarding flag is cleared
          document.getElementById('modalOverlay').classList.remove('visible');

          await render();
          UI.toast('Key pair generated!', 'success');
        } catch (err) {
          UI.hideLoading();
          UI.toast('Key generation failed: ' + err.message, 'error');
        }
      });
    });
  }

  /* ── Import modal ──────────────────────────────── */
  function showImportModal() {
    UI.openModal(`
      <h2 class="modal-title">Import Key</h2>
      <div class="info-panel">
        Paste an ASCII-armored public key or private key block.
      </div>
      <div class="form-group">
        <label class="form-label" for="importKeyArmored">Armored Key</label>
        <textarea class="form-input form-textarea" id="importKeyArmored"
          placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;…&#10;-----END PGP PUBLIC KEY BLOCK-----"
          rows="8" spellcheck="false" autocorrect="off" autocapitalize="off"></textarea>
      </div>
      <div id="importPassSection" style="display:none">
        <div class="info-panel warn">
          Private key detected. Set a passphrase to encrypt it in local storage.
        </div>
        <div class="form-group">
          <label class="form-label" for="importPass">Storage Passphrase</label>
          <div class="input-group">
            <input type="password" class="form-input" id="importPass"
              placeholder="Passphrase for local storage" autocomplete="new-password">
            <button class="input-reveal" data-target="importPass" type="button" aria-label="Show passphrase">${revealIconHTML()}</button>
          </div>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-ghost" id="importCancel">Cancel</button>
        <button class="btn btn-primary" id="importConfirm">Import</button>
      </div>
    `, () => {
      let detectedPrivate = false;
      const textarea = document.getElementById('importKeyArmored');
      textarea.addEventListener('input', () => {
        detectedPrivate = textarea.value.includes('BEGIN PGP PRIVATE KEY') ||
                          textarea.value.includes('BEGIN PGP SECRET KEY');
        document.getElementById('importPassSection').style.display =
          detectedPrivate ? 'block' : 'none';
        // Rebind reveal for newly shown field
        if (detectedPrivate) bindRevealToggles(document.getElementById('importPassSection'));
      });

      document.getElementById('importCancel').addEventListener('click', UI.closeModal);
      document.getElementById('importConfirm').addEventListener('click', async () => {
        const armoredKey = textarea.value.trim();
        if (!armoredKey) return UI.toast('Please paste a key.', 'error');

        // For public keys: run the collision check BEFORE closing the modal,
        // so we can show an error inside the modal without any loading flash.
        if (!detectedPrivate) {
          let meta, armoredPub;
          try {
            meta      = await PGP.inspectKey(armoredKey);
            armoredPub = (await openpgp.readKey({ armoredKey })).armor();
          } catch (err) {
            return UI.toast('Invalid key: ' + err.message, 'error');
          }

          // Check DB for a private key with the same fingerprint
          const allKeys = await DB.getAll();
          const conflict = allKeys.find(k =>
            k.hasPrivate && (
              k.fingerprint === meta.fingerprint ||
              k.publicKeyArmored === armoredPub
            )
          );

          if (conflict) {
            // Show hard-block error inside the modal — do NOT close, do NOT import
            const existing = document.getElementById('importErrorBanner');
            if (existing) existing.remove();
            const banner = document.createElement('div');
            banner.id = 'importErrorBanner';
            banner.className = 'import-error-banner';
            const shortFP = conflict.fingerprint.slice(-16).match(/.{1,4}/g).join(' ');
            banner.innerHTML = `
              <strong>Error:</strong> a private key with fingerprint
              <code>${shortFP}</code> already exists in My Keys.<br>
              Delete the private key first before importing its public key as a contact.`;
            const actions = document.querySelector('.modal-actions');
            actions.parentNode.insertBefore(banner, actions);
            return; // hard stop — user must cancel or delete first
          }

          // No conflict — safe to import
          UI.closeModal();
          UI.showLoading('Importing key…');
          try {
            await DB.put({
              id: meta.fingerprint, name: meta.name, email: meta.email,
              keyType: meta.keyType, fingerprint: meta.fingerprint, keyId: meta.keyId,
              publicKeyArmored: armoredPub,
              encryptedPrivateKey: null, salt: null, iv: null,
              hasPrivate: false, createdAt: new Date().toISOString()
            });
            UI.hideLoading();
            await render();
            UI.toast('Key imported!', 'success');
          } catch (err) {
            UI.hideLoading();
            UI.toast('Import failed: ' + err.message, 'error');
          }
          return;
        }

        // Private key import path (unchanged)
        const pass = document.getElementById('importPass')?.value || '';
        if (!pass) return UI.toast('Enter a storage passphrase.', 'error');
        UI.closeModal();
        UI.showLoading('Importing key…');
        try {
          const privKey  = await openpgp.readPrivateKey({ armoredKey });
          const armoredPub = privKey.toPublic().armor();
          const meta = await PGP.inspectKey(armoredPub);
          const { encryptedPrivateKey, salt, iv } =
            await Crypto.encryptPrivateKey(privKey.armor(), pass);
          await DB.put({
            id: meta.fingerprint, name: meta.name, email: meta.email,
            keyType: meta.keyType, fingerprint: meta.fingerprint, keyId: meta.keyId,
            publicKeyArmored: armoredPub, encryptedPrivateKey, salt, iv,
            hasPrivate: true, createdAt: new Date().toISOString()
          });
          UI.hideLoading();
          await render();
          UI.toast('Key imported!', 'success');
        } catch (err) {
          UI.hideLoading();
          UI.toast('Import failed: ' + err.message, 'error');
        }
      });
    });
  }

  /* ── Export / Delete modals ────────────────────── */
  function showExportPublic(record) {
    UI.openModal(`
      <h2 class="modal-title">Public Key</h2>
      <div class="key-fingerprint" style="margin-bottom:14px">${UI.formatFingerprint(record.fingerprint)}</div>
      <div class="output-header" style="margin-bottom:8px">
        <span class="output-label">Share this key freely</span>
        <button class="copy-btn" id="expPubCopy">${copyIconHTML()} Copy</button>
      </div>
      <div class="output-box" style="max-height:260px">${escHtml(record.publicKeyArmored)}</div>
      <div class="modal-actions">
        <button class="btn btn-primary btn-full" id="expPubClose">Done</button>
      </div>
    `, () => {
      document.getElementById('expPubClose').addEventListener('click', UI.closeModal);
      document.getElementById('expPubCopy').addEventListener('click', function () {
        UI.copyText(record.publicKeyArmored, this);
      });
    });
  }

  function showExportPrivate(record) {
    UI.openModal(`
      <h2 class="modal-title">Export Private Key</h2>
      <div class="info-panel warn">⚠ Never share your private key with anyone.</div>
      <div class="form-group">
        <label class="form-label" for="expPrivPass">Enter passphrase to unlock</label>
        <div class="input-group">
          <input type="password" class="form-input" id="expPrivPass"
            placeholder="Your key passphrase" autocomplete="off">
          <button class="input-reveal" data-target="expPrivPass" type="button" aria-label="Show passphrase">${revealIconHTML()}</button>
        </div>
      </div>
      <div class="modal-actions">
        <button class="btn btn-ghost" id="expPrivCancel">Cancel</button>
        <button class="btn btn-primary" id="expPrivConfirm">Unlock &amp; Export</button>
      </div>
    `, () => {
      document.getElementById('expPrivCancel').addEventListener('click', UI.closeModal);
      document.getElementById('expPrivConfirm').addEventListener('click', async () => {
        const pass = document.getElementById('expPrivPass').value;
        if (!pass) return UI.toast('Enter your passphrase.', 'error');
        UI.showLoading('Decrypting…');
        try {
          const armoredPriv = await Crypto.decryptPrivateKey(
            record.encryptedPrivateKey, record.salt, record.iv, pass
          );
          UI.hideLoading();
          UI.closeModal();
          UI.openModal(`
            <h2 class="modal-title">Private Key</h2>
            <div class="info-panel warn">⚠ Store this securely. Do not share.</div>
            <div class="output-header" style="margin-bottom:8px">
              <span class="output-label">Private key (armored)</span>
              <button class="copy-btn" id="expPrivCopy">${copyIconHTML()} Copy</button>
            </div>
            <div class="output-box" style="max-height:240px">${escHtml(armoredPriv)}</div>
            <div class="modal-actions">
              <button class="btn btn-primary btn-full" id="expPrivDone">Done</button>
            </div>
          `, () => {
            document.getElementById('expPrivDone').addEventListener('click', UI.closeModal);
            document.getElementById('expPrivCopy').addEventListener('click', function () {
              UI.copyText(armoredPriv, this);
            });
          });
        } catch {
          UI.hideLoading();
          UI.toast('Wrong passphrase.', 'error');
        }
      });
    });
  }

  function confirmDelete(record) {
    UI.openModal(`
      <h2 class="modal-title">Delete Key?</h2>
      <p style="color:var(--text-muted);font-size:14px;margin-bottom:20px;line-height:1.6">
        Permanently remove <strong style="color:var(--text)">${escHtml(record.name)}</strong>'s
        ${record.hasPrivate ? 'key pair' : 'public key'} from this device.
        Exported copies will not be affected.
      </p>
      <div class="modal-actions">
        <button class="btn btn-ghost" id="delCancel">Cancel</button>
        <button class="btn btn-danger" id="delConfirm">Delete</button>
      </div>
    `, () => {
      document.getElementById('delCancel').addEventListener('click', UI.closeModal);
      document.getElementById('delConfirm').addEventListener('click', async () => {
        await DB.delete(record.id);
        UI.closeModal();
        await render();
        UI.toast('Key deleted.', 'info');
      });
    });
  }

  return { render, bindEvents, showFirstTimeSetup };
})();

/* ════════════════════════════════════════════════
   9. ENCRYPT TAB  (unchanged)
   ════════════════════════════════════════════════ */
const EncryptTab = (() => {

  function refreshRecipients(keys) {
    const contacts  = keys.filter(k => !k.hasPrivate)
      .sort((a, b) => a.name.localeCompare(b.name));
    const container = document.getElementById('encryptRecipients');
    if (contacts.length === 0) {
      container.innerHTML = `
        <div class="empty-tip">
          <span class="empty-tip-icon">👤</span>
          <span>No contacts yet. Import a recipient's public key in the <strong>Keys</strong> tab first.</span>
        </div>`;
      return;
    }
    container.innerHTML = contacts.map(k => `
      <label class="key-checkbox-item" data-id="${k.id}">
        <input type="checkbox" value="${k.id}">
        <div class="key-check-mark">
          <svg width="10" height="8" viewBox="0 0 10 8" fill="none"><path d="M1 4l3 3 5-6" stroke="#060610" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </div>
        <div class="key-checkbox-info">
          <div class="key-checkbox-name">${escHtml(k.name)}</div>
          <div class="key-checkbox-email">${escHtml(k.email)}</div>
        </div>
      </label>
    `).join('');
    container.querySelectorAll('.key-checkbox-item').forEach(item => {
      const k = contacts.find(c => c.id === item.dataset.id);
      if (k && k.isDefault) {
        const cb = item.querySelector('input[type=checkbox]');
        cb.checked = true;
        item.classList.add('selected');
      }
      item.addEventListener('click', () => {
        const cb = item.querySelector('input[type=checkbox]');
        cb.checked = !cb.checked;
        item.classList.toggle('selected', cb.checked);
      });
    });
  }

  function refreshSignKeys(keys) {
    const sel  = document.getElementById('encryptSignKey');
    const mine = keys.filter(k => k.hasPrivate)
      .sort((a, b) => a.name.localeCompare(b.name));
    sel.innerHTML = mine.length === 0
      ? '<option value="">No personal keys — generate one first</option>'
      : mine.map(k => `<option value="${k.id}">${escHtml(k.name)} &lt;${escHtml(k.email)}&gt;</option>`).join('');
    const defaultKey = mine.find(k => k.isDefault);
    if (defaultKey) sel.value = defaultKey.id;
  }

  function bindEvents() {
    document.getElementById('btnEncrypt').addEventListener('click', async () => {
      const checkedIds = [...document.querySelectorAll('#encryptRecipients input:checked')]
        .map(cb => cb.value);
      const plaintext  = document.getElementById('encryptInput').value;
      const signKeyId  = document.getElementById('encryptSignKey').value;
      const passphrase = document.getElementById('encryptPassphrase').value;

      if (checkedIds.length === 0)  return UI.toast('Select at least one recipient.', 'error');
      if (!plaintext.trim())        return UI.toast('Message cannot be empty.', 'error');
      if (!signKeyId)               return UI.toast('No signing key. Generate your key pair first.', 'error');
      if (!passphrase)              return UI.toast('Enter your passphrase to sign.', 'error');

      UI.showLoading('Encrypting & signing…');
      try {
        const recipientRecords = await Promise.all(checkedIds.map(id => DB.get(id)));
        const signingRecord    = await DB.get(signKeyId);
        const encrypted = await PGP.encrypt(plaintext, recipientRecords, signingRecord, passphrase);

        document.getElementById('encryptResult').textContent = encrypted;
        document.getElementById('encryptOutput').classList.add('visible');
        document.getElementById('encryptPassphrase').value = '';
        UI.hideLoading();
        UI.toast('Encrypted & signed!', 'success');
      } catch (err) {
        UI.hideLoading();
        const isWrongPass = /aes-gcm|decrypt|operation|passphrase/i.test(err.message);
        UI.toast(isWrongPass ? 'Wrong passphrase.' : 'Encryption failed: ' + err.message, 'error');
      }
    });

    document.getElementById('btnCopyEncrypt').addEventListener('click', function () {
      UI.copyText(document.getElementById('encryptResult').textContent, this);
    });
  }

  return { refreshRecipients, refreshSignKeys, bindEvents };
})();

/* ════════════════════════════════════════════════
   10. DECRYPT TAB  (unchanged)
   ════════════════════════════════════════════════ */
const DecryptTab = (() => {

  function refreshKeys(keys) {
    const sel  = document.getElementById('decryptKey');
    const mine = keys.filter(k => k.hasPrivate)
      .sort((a, b) => a.name.localeCompare(b.name));
    sel.innerHTML = mine.length === 0
      ? '<option value="">No personal keys available</option>'
      : mine.map(k => `<option value="${k.id}">${escHtml(k.name)} &lt;${escHtml(k.email)}&gt;</option>`).join('');
    const defaultKey = mine.find(k => k.isDefault);
    if (defaultKey) sel.value = defaultKey.id;
  }

  function renderSigStatus(state, signerName, signerEmail, signerKeyId) {
    const banner = document.getElementById('sigStatusBanner');
    const configs = {
      valid: {
        cls: 'sig-valid', icon: '✓', title: 'Signature Valid',
        detail: `Signed by <strong>${escHtml(signerName || 'Unknown')}</strong>${signerEmail ? ` &lt;${escHtml(signerEmail)}&gt;` : ''} — identity confirmed.`
      },
      invalid: {
        cls: 'sig-invalid', icon: '✗', title: 'Signature Verification FAILED',
        detail: 'This message\'s signature is <strong>invalid</strong>. It may have been tampered with. <strong>Do not trust its contents.</strong>'
      },
      unsigned: {
        cls: 'sig-unsigned', icon: '⚠', title: 'Unsigned Message',
        detail: 'This message has no digital signature. The sender\'s identity <strong>cannot be verified</strong>. Anyone could have written it.'
      },
      unknown_key: {
        cls: 'sig-unknown', icon: '?', title: 'Signer Unknown',
        detail: `Message is signed (Key ID: <code>${signerKeyId || '?'}</code>), but the signing key is <strong>not in your keyring</strong>. Import the sender's public key to verify their identity.`
      }
    };
    const cfg = configs[state] || configs.unsigned;
    banner.className = `sig-status-banner ${cfg.cls}`;
    banner.innerHTML = `
      <div class="sig-status-icon">${cfg.icon}</div>
      <div class="sig-status-body">
        <div class="sig-status-title">${cfg.title}</div>
        <div class="sig-status-detail">${cfg.detail}</div>
      </div>`;
    banner.style.display = 'flex';
  }

  function bindEvents() {
    document.getElementById('btnDecrypt').addEventListener('click', async () => {
      const armoredMessage = document.getElementById('decryptInput').value.trim();
      const keyId          = document.getElementById('decryptKey').value;
      const passphrase     = document.getElementById('decryptPassphrase').value;

      if (!armoredMessage) return UI.toast('Paste the encrypted message.', 'error');
      if (!keyId)          return UI.toast('Select a decryption key.', 'error');
      if (!passphrase)     return UI.toast('Enter your passphrase.', 'error');

      document.getElementById('decryptOutput').classList.remove('visible');
      document.getElementById('sigStatusBanner').style.display = 'none';

      UI.showLoading('Decrypting & verifying…');
      try {
        const record  = await DB.get(keyId);
        const allKeys = await DB.getAll();
        const { plaintext, sigStatus, signerKeyId, signerName, signerEmail } =
          await PGP.decrypt(armoredMessage, record, passphrase, allKeys);

        document.getElementById('decryptResult').textContent = plaintext;
        document.getElementById('decryptOutput').classList.add('visible');
        renderSigStatus(sigStatus, signerName, signerEmail, signerKeyId);
        document.getElementById('decryptPassphrase').value = '';
        UI.hideLoading();

        const toastMap = {
          valid:       ['Decrypted — signature valid!', 'success'],
          invalid:     ['⚠ Decrypted — signature INVALID!', 'error'],
          unsigned:    ['Decrypted — message is unsigned.', 'info'],
          unknown_key: ['Decrypted — signer key not in keyring.', 'info']
        };
        const [msg, type] = toastMap[sigStatus] || ['Decrypted.', 'success'];
        UI.toast(msg, type, 4000);
      } catch (err) {
        UI.hideLoading();
        const isWrongPass = /aes-gcm|decrypt|operation|passphrase|session/i.test(err.message);
        UI.toast(isWrongPass ? 'Wrong passphrase or incorrect key.' : 'Decryption failed: ' + err.message, 'error');
      }
    });

    document.getElementById('btnCopyDecrypt').addEventListener('click', function () {
      UI.copyText(document.getElementById('decryptResult').textContent, this);
    });
  }

  return { refreshKeys, bindEvents };
})();

/* ════════════════════════════════════════════════
   LEGAL OVERLAY MODULE
   - First launch: shows full sheet with accept checkbox, blocks app
   - Subsequent: toggled by the ⓘ icon, swipe-down to dismiss
   ════════════════════════════════════════════════ */
const LegalOverlay = (() => {
  const ACCEPTED_KEY = 'pgphone_legal_accepted_v1';

  let sheet, scrollArea, overlay;
  // Swipe state
  let touchStartY = 0, touchStartScroll = 0, isSwiping = false;

  function hasAccepted() {
    try { return localStorage.getItem(ACCEPTED_KEY) === '1'; } catch { return false; }
  }

  function markAccepted() {
    try { localStorage.setItem(ACCEPTED_KEY, '1'); } catch {}
  }

  function show(isFirstTime) {
    overlay    = document.getElementById('legalOverlay');
    sheet      = document.getElementById('legalSheet');
    scrollArea = document.getElementById('legalScrollArea');
    const acceptBlock = document.getElementById('legalAcceptBlock');
    const checkbox    = document.getElementById('legalCheckbox');
    const acceptBtn   = document.getElementById('btnLegalAccept');

    // Show or hide acceptance block depending on context
    acceptBlock.style.display = isFirstTime ? 'flex' : 'none';

    if (isFirstTime) {
      // Ensure checkbox starts unchecked
      checkbox.checked  = false;
      acceptBtn.disabled = true;

      checkbox.addEventListener('change', () => {
        acceptBtn.disabled = !checkbox.checked;
      }, { once: false });

      acceptBtn.addEventListener('click', () => {
        if (!checkbox.checked) return;
        markAccepted();
        hide();
        // Proceed with normal app init flow
        App._legalDone();
      }, { once: true });
    }

    // Reset scroll and sheet position
    scrollArea.scrollTop = 0;
    sheet.style.transform = '';
    sheet.classList.remove('swiping');

    overlay.classList.add('visible');
    bindSwipe();
  }

  function hide() {
    overlay    = document.getElementById('legalOverlay');
    sheet      = document.getElementById('legalSheet');
    overlay.classList.remove('visible');
    sheet.style.transform = '';
    sheet.classList.remove('swiping');
  }

  function bindSwipe() {
    sheet = document.getElementById('legalSheet');
    scrollArea = document.getElementById('legalScrollArea');

    sheet.addEventListener('touchstart', onTouchStart, { passive: true });
    sheet.addEventListener('touchmove',  onTouchMove,  { passive: false });
    sheet.addEventListener('touchend',   onTouchEnd,   { passive: true });
  }

  function onTouchStart(e) {
    touchStartY      = e.touches[0].clientY;
    touchStartScroll = scrollArea.scrollTop;
    isSwiping        = false;
  }

  function onTouchMove(e) {
    const dy = e.touches[0].clientY - touchStartY; // positive = finger moving down

    // Only intercept downward drag when scroll area is already at top
    if (dy > 0 && scrollArea.scrollTop <= 0) {
      isSwiping = true;
      sheet.classList.add('swiping');
      // Clamp: don't let sheet go above its resting position
      const clamped = Math.max(0, dy);
      sheet.style.transform = `translateY(${clamped}px)`;
      e.preventDefault(); // prevent body scroll
    } else {
      isSwiping = false;
      sheet.classList.remove('swiping');
    }
  }

  function onTouchEnd(e) {
    if (!isSwiping) return;
    const dy = e.changedTouches[0].clientY - touchStartY;
    sheet.classList.remove('swiping');

    if (dy > 100) {
      // Sufficient downward swipe — animate out and hide
      // Only dismiss if user has already accepted (not first-time mandatory)
      if (hasAccepted()) {
        sheet.style.transition = 'transform 0.3s cubic-bezier(0.4, 0, 1, 1)';
        sheet.style.transform  = `translateY(100%)`;
        setTimeout(() => {
          sheet.style.transition = '';
          sheet.style.transform  = '';
          hide();
        }, 320);
      } else {
        // First-time: snap back — can't dismiss without accepting
        sheet.style.transform = '';
      }
    } else {
      // Not enough — snap back
      sheet.style.transform = '';
    }
    isSwiping = false;
  }

  return {
    init() {
      // Wire the ⓘ icon button (always available after first acceptance)
      document.getElementById('btnShowInfo').addEventListener('click', () => {
        show(false);
      });

      if (!hasAccepted()) {
        // First time — show immediately, block app
        show(true);
        return false; // tell App.init that legal gate is blocking
      }
      return true; // legal already accepted, proceed normally
    }
  };
})();

/* ════════════════════════════════════════════════
   11. APP CONTROLLER
   ════════════════════════════════════════════════ */
const App = {

  /** True while mandatory first-time setup is in progress. */
  _onboarding: false,

  refreshKeySelectors(keys) {
    EncryptTab.refreshRecipients(keys);
    EncryptTab.refreshSignKeys(keys);
    DecryptTab.refreshKeys(keys);
  },

  bindGlobalEvents() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.tab-btn').forEach(b => {
          b.classList.toggle('active', b.dataset.tab === tab);
          b.setAttribute('aria-selected', b.dataset.tab === tab);
        });
        document.querySelectorAll('.tab-panel').forEach(p => {
          p.classList.toggle('active', p.id === `tab-${tab}`);
        });
      });
    });

    document.getElementById('modalOverlay').addEventListener('click', e => {
      if (e.target.id === 'modalOverlay' && !App._onboarding) UI.closeModal();
    });

    bindRevealToggles(document);
  },

  /** Called by LegalOverlay after user accepts on first run */
  async _legalDone() {
    await this._startApp();
  },

  async _startApp() {
    await KeysTab.render();
    const keys = await DB.getAll();
    if (keys.length === 0) {
      App._onboarding = true;
      KeysTab.showFirstTimeSetup();
    }
  },

  async init() {
    this.bindGlobalEvents();
    KeysTab.bindEvents();
    EncryptTab.bindEvents();
    DecryptTab.bindEvents();

    const legalOk = LegalOverlay.init();
    if (legalOk) {
      // Already accepted — start normally
      await this._startApp();
    }
    // else: LegalOverlay is showing; _legalDone() will trigger _startApp() after acceptance

    console.log('[PGPhone v0.7.4] Initialized. All operations strictly local.');
  }
};

/* ════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════ */
function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function copyIconHTML() {
  return `<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><rect x="4" y="4" width="7" height="7" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M2 8V2.5A.5.5 0 0 1 2.5 2H8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>`;
}

function revealIconHTML() {
  return `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true"><ellipse cx="9" cy="9" rx="7" ry="5" stroke="currentColor" stroke-width="1.5"/><circle cx="9" cy="9" r="2.5" stroke="currentColor" stroke-width="1.5"/></svg>`;
}

/* Boot */
document.addEventListener('DOMContentLoaded', () => App.init());
