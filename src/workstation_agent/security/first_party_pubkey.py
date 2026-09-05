"""First-party plugin signing pubkey — baked into the build.

The corresponding private key lives in the release CI as a GitHub Actions
secret (never in the tree). Any first-party plugin signed with the matching
private key verifies against this pubkey at load time. The build pipeline
(SPEC-10) will overwrite this file from the ``PC_AGENT_FIRST_PARTY_PUBKEY``
env at wheel-build time; the value below is the framework's development key
so the plugin suite verifies out of the box.
"""

FIRST_PARTY_PUBKEY_HEX = "e99faba08ffc2eef3552778ddb63c0dce39a08083405a62ea76a89594cf8084a"
FIRST_PARTY_PUBKEY = bytes.fromhex(FIRST_PARTY_PUBKEY_HEX)
