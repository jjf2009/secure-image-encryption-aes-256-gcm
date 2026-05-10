/**
 * PASSWORD_STRENGTH.JS
 * ====================
 * Password validation and strength evaluation.
 * Provides real-time feedback to users about password security
 * and visual indicators of strength levels.
 */

import {
  MIN_PASSWORD_LENGTH,
  STRONG_PASSWORD_LENGTH,
  COMMON_PASSWORDS,
  SPECIAL_CHAR_PATTERN,
  STRENGTH_SCORE_MAX,
  STRENGTH_PERCENTAGES,
  STRENGTH_CLASSES,
} from "../utils/constants.js";

/**
 * Evaluates a password against security criteria.
 * Returns an object with boolean flags for each criterion met.
 *
 * CRITERIA EVALUATED:
 * - minLength: At least MIN_PASSWORD_LENGTH (8) characters
 * - longLength: At least STRONG_PASSWORD_LENGTH (12) characters
 * - upperLower: Contains both uppercase and lowercase letters
 * - number: Contains at least one digit
 * - special: Contains at least one special character
 * - notCommon: Not in the common weak passwords list
 *
 * @param {string} password - Password to evaluate
 * @returns {Object} Object with boolean flags for each criterion
 */
export const evaluatePasswordCriteria = (password) => {
  const lower = password.toLowerCase();
  return {
    minLength: password.length >= MIN_PASSWORD_LENGTH,
    longLength: password.length >= STRONG_PASSWORD_LENGTH,
    upperLower: /[a-z]/.test(password) && /[A-Z]/.test(password),
    number: /\d/.test(password),
    special: SPECIAL_CHAR_PATTERN.test(password),
    notCommon: password.length > 0 && !COMMON_PASSWORDS.includes(lower),
  };
};

/**
 * Determines password strength level based on criteria met.
 * Uses a scoring system where more criteria = stronger password.
 *
 * STRENGTH LEVELS:
 * - weak (25%): Less than minimum length or <=2 criteria met
 * - fair (50%): 3-4 criteria met
 * - strong (75%): 5 criteria met
 * - veryStrong (100%): All 6 criteria met
 *
 * @param {Object} criteria - Result from evaluatePasswordCriteria()
 * @returns {Object} Object with level, label, and percentage
 */
export const determineStrength = (criteria) => {
  const metCriteriaCount = Object.values(criteria).filter(Boolean).length;

  // Minimum length is mandatory - fail if not met
  if (!criteria.minLength) {
    return {
      level: "weak",
      label: "Weak",
      percentage: STRENGTH_PERCENTAGES.weak,
    };
  }

  // Score based on number of criteria met
  if (metCriteriaCount <= STRENGTH_SCORE_MAX.weak) {
    return {
      level: "weak",
      label: "Weak",
      percentage: STRENGTH_PERCENTAGES.weak,
    };
  }
  if (metCriteriaCount <= STRENGTH_SCORE_MAX.fair) {
    return {
      level: "fair",
      label: "Fair",
      percentage: STRENGTH_PERCENTAGES.fair,
    };
  }
  if (metCriteriaCount <= STRENGTH_SCORE_MAX.strong) {
    return {
      level: "strong",
      label: "Strong",
      percentage: STRENGTH_PERCENTAGES.strong,
    };
  }

  return {
    level: "veryStrong",
    label: "Very Strong",
    percentage: STRENGTH_PERCENTAGES.veryStrong,
  };
};

/**
 * Updates the UI to display current password strength in real-time.
 * This function is called on every password input change.
 *
 * UPDATES:
 * - Strength bar fill percentage and color
 * - Strength label text and color
 * - Criteria checkmarks (visual feedback for each requirement)
 * - Warning message if minimum length not met
 * - Encrypt button disabled state
 *
 * @param {HTMLElement} passwordInput - Password input element
 * @param {HTMLElement} strengthBar - Progress bar element
 * @param {HTMLElement} strengthLabel - Label text element
 * @param {HTMLElement} strengthWarning - Warning message element
 * @param {Object} criteriaCheckboxes - Map of criterion name to checkbox element
 * @param {HTMLElement} encryptButton - Encrypt button to enable/disable
 * @param {boolean} encryptInProgress - Whether encryption is currently running
 * @returns {Object} Current strength level and metadata
 */
export const updatePasswordStrengthUI = ({
  passwordInput,
  strengthBar,
  strengthLabel,
  strengthWarning,
  criteriaCheckboxes,
  encryptButton,
  encryptInProgress,
}) => {
  // Get current password and evaluate it
  const password = passwordInput?.value || "";
  const criteria = evaluatePasswordCriteria(password);
  const strength = determineStrength(criteria);
  const labelClass = STRENGTH_CLASSES[strength.level];

  // Update visual strength indicator
  if (strengthBar) {
    strengthBar.style.width = `${strength.percentage}%`;
    strengthBar.className = `strength-bar ${labelClass}`;
  }

  if (strengthLabel) {
    strengthLabel.textContent = strength.label;
    strengthLabel.className = `strength-text ${labelClass}`;
  }

  // Show warning if minimum length not met
  if (strengthWarning) {
    strengthWarning.style.display = criteria.minLength ? "none" : "inline";
    strengthWarning.textContent = criteria.minLength
      ? ""
      : `Minimum ${MIN_PASSWORD_LENGTH} characters required.`;
  }

  // Update individual criterion checkmarks
  Object.entries(criteriaCheckboxes).forEach(([key, checkbox]) => {
    if (!checkbox) return;
    const met = Boolean(criteria[key]);
    checkbox.checked = met;

    // Add visual styling to parent criteria item
    const item = checkbox.closest(".criteria-item");
    if (item) {
      item.classList.toggle("met", met);
    }
  });

  // Enable/disable encrypt button based on strength
  if (encryptButton) {
    encryptButton.disabled = encryptInProgress || strength.level === "weak";
  }

  return strength;
};
