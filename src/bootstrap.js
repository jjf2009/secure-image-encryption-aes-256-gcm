/**
 * BOOTSTRAP.JS
 * ============
 * Application entrypoint that renders HTML layout first,
 * then loads the main app orchestrator.
 */

import { renderAppLayout } from "./ui/layoutTemplate.js";

const appRoot = document.getElementById("app-root");
renderAppLayout(appRoot);

// Load app after DOM structure exists so element caching is reliable.
await import("./app.js");
