'use strict'

// Load the platform-specific `.node` binary produced by `napi build` / `cargo build`.
// After `npx @napi-rs/cli build`, the CLI may replace this file with a multi-platform loader.
try {
  module.exports = require('./agentfirewall.node')
} catch (e) {
  try {
    module.exports = require(`./agentfirewall.${process.platform}-${process.arch}.node`)
  } catch (e2) {
    throw new Error(
      'Agent FirewallKit native addon not found. Build with: npx @napi-rs/cli build (from this package directory).',
      { cause: e2 }
    )
  }
}
