/**
 * LAYOUT_TEMPLATE.JS
 * ==================
 * Provides the main HTML structure for the application.
 * This keeps index.html focused on document metadata and script loading.
 */

/**
 * Builds the main app layout markup.
 *
 * @returns {string} HTML string for the page body content
 */
export const getAppLayoutMarkup = () => `
  <div class="container">
    <header>
      <h1>SecureImage</h1>
      <p>
        Shield your visual data with AES-256-GCM encryption. Private, secure,
        and purely client-side.
      </p>
    </header>

    <main class="main-grid">
      <section class="card">
        <div class="card-header">
          <h2>Encrypt Image</h2>
          <p>Convert your image to a secure text-based data block.</p>
        </div>

        <div class="form-group">
          <label for="image-upload">Source Image</label>
          <input type="file" id="image-upload" accept="image/*" />
          <p class="helper-text">Supports JPEG, PNG, WEBP, etc.</p>
        </div>

        <div class="form-group">
          <label for="encrypt-password">Secret Passphrase</label>
          <input
            type="password"
            id="encrypt-password"
            placeholder="e.g. your-secure-password"
          />
          <div class="password-strength-block" id="password-strength-block">
            <div class="strength-row">
              <span
                class="strength-text strength-weak"
                id="password-strength-label"
                aria-live="polite"
                >Weak</span
              >
              <span class="strength-warning" id="password-strength-warning"
                >Minimum 8 characters required.</span
              >
            </div>
            <div class="strength-meter" aria-hidden="true">
              <div
                class="strength-bar strength-weak"
                id="password-strength-bar"
                style="width: 0%"
              ></div>
            </div>
            <ul class="criteria-list" id="password-criteria-list">
              <li class="criteria-item" data-criterion="minLength">
                <input type="checkbox" id="criteria-length" disabled />
                <label for="criteria-length">At least 8 characters</label>
              </li>
              <li class="criteria-item" data-criterion="longLength">
                <input type="checkbox" id="criteria-long" disabled />
                <label for="criteria-long">12+ characters</label>
              </li>
              <li class="criteria-item" data-criterion="upperLower">
                <input type="checkbox" id="criteria-case" disabled />
                <label for="criteria-case"
                  >Uppercase & lowercase letters</label
                >
              </li>
              <li class="criteria-item" data-criterion="number">
                <input type="checkbox" id="criteria-number" disabled />
                <label for="criteria-number">Contains numbers</label>
              </li>
              <li class="criteria-item" data-criterion="special">
                <input
                  type="checkbox"
                  id="criteria-special"
                  aria-describedby="criteria-special-help"
                  disabled
                />
                <label for="criteria-special"
                  >Contains special characters</label
                >
              </li>
              <li class="criteria-item" data-criterion="notCommon">
                <input type="checkbox" id="criteria-common" disabled />
                <label for="criteria-common">Not a common password</label>
              </li>
            </ul>
            <p class="helper-text" id="criteria-special-help"></p>
          </div>
        </div>

        <button id="btn-encrypt" class="btn">
          <span class="spinner" id="encrypt-spinner"></span>
          <span>Encrypt Now</span>
        </button>

        <div id="encrypt-status" class="status-box"></div>

        <div
          id="download-area"
          style="display: none; margin-top: 1.5rem; text-align: center"
        >
          <a
            id="btn-download-txt"
            class="btn btn-secondary"
            style="text-decoration: none; width: auto; display: inline-flex"
          >
            Download encrypt.txt
          </a>
          <p class="helper-text">
            Save this file, you'll need it for decryption.
          </p>
        </div>
      </section>

      <section class="card">
        <div class="card-header">
          <h2>Decrypt Image</h2>
          <p>
            Restore encrypted blocks back into their original visual form.
          </p>
        </div>

        <div class="form-group">
          <label for="encrypted-text">Data Block (or upload file)</label>
          <textarea
            id="encrypted-text"
            placeholder="IV:Tag:Data..."
          ></textarea>
          <div style="margin-top: 0.75rem">
            <input type="file" id="txt-upload" accept=".txt" />
          </div>
        </div>

        <div class="form-group">
          <label for="decrypt-password">Original Passphrase</label>
          <input
            type="password"
            id="decrypt-password"
            placeholder="The password used during encryption"
          />
        </div>

        <button id="btn-decrypt" class="btn btn-secondary">
          <span class="spinner" id="decrypt-spinner"></span>
          <span>Decrypt & Restore</span>
        </button>

        <div id="decrypt-status" class="status-box"></div>

        <div id="preview-area" class="preview-box">
          <img id="decrypted-preview" alt="Decrypted Outcome" />
        </div>

        <a
          id="btn-download-img"
          class="btn"
          style="
            display: none;
            width: 100%;
            margin-top: 2rem;
            text-decoration: none;
          "
        >
          Download Restored Image
        </a>
      </section>
    </main>

    <p class="attack-explainer">
      AES-GCM uses an authentication tag to guarantee integrity. Even a single
      bit change in ciphertext causes decryption to fail — this is called
      authenticated encryption.
    </p>

    <footer>
      <p>&copy; 2026 Project SecureImage // Client-Side AES-256-GCM Protocol</p>
    </footer>
  </div>
`;

/**
 * Renders the full app layout into the provided host element.
 *
 * @param {HTMLElement} host - Root element where layout should be injected
 */
export const renderAppLayout = (host) => {
  if (!host) {
    throw new Error("App root element not found.");
  }

  host.innerHTML = getAppLayoutMarkup();
};
