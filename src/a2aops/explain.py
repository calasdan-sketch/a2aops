"""``a2aops explain CODE``: what a diagnostic means and how to fix it.

One line of meaning and one line of fix per code. ``tests/test_round3.py``
fails if a code appears in the source without an entry here, so this table
cannot silently fall behind the checks.
"""

from __future__ import annotations

# code: (meaning, fix)
CODES: dict[str, tuple[str, str]] = {
    # ---- card structure
    "E001": ("The document is not a JSON object.", "An AgentCard is a single JSON object."),
    "E101": ("A field the AgentCard schema requires is missing.", "Add it; see spec section 4.4.1 / a2a.proto AgentCard."),
    "E102": ("supportedInterfaces is missing, empty or not an array.", "List at least one interface: {url, protocolBinding, protocolVersion}."),
    "E103": ("An entry of supportedInterfaces is not an object.", "Make each entry an object."),
    "E104": ("An interface lacks a required field (url, protocolBinding or protocolVersion).", "Add the missing field."),
    "E105": ("An interface url is not a valid endpoint for its binding.", "Use an absolute http(s) URL (JSONRPC, HTTP+JSON) or host:port (GRPC)."),
    "E106": ("protocolBinding is not a string.", "Use JSONRPC, GRPC or HTTP+JSON."),
    "E107": ("capabilities is not an object.", "Use an object such as {\"streaming\": true}."),
    "E108": ("defaultInputModes/defaultOutputModes is not a non-empty array of strings.", "List media types, e.g. [\"text/plain\"]."),
    "E109": ("skills is not an array.", "Use an array of skill objects."),
    "E110": ("A skill is not an object.", "Make each skill an object."),
    "E111": ("A skill lacks a required field (id, name, description, tags).", "Add the missing field."),
    "E112": ("A skill's tags is not a non-empty array of strings.", "Give each skill at least one string tag."),
    "E113": ("Two skills share the same id.", "Skill ids must be unique; clients route by id."),
    "E114": ("securityRequirements is not an array.", "Use an array of requirement objects."),
    "E115": ("A securityRequirements entry is not in the v1.0 wire shape.", "Use {\"schemes\": {\"<scheme>\": {\"list\": [scopes]}}}."),
    "E120": ("A field has the wrong JSON type for the proto definition.", "Change the value to the type named in the message."),
    "E121": ("A required field of a nested message is missing.", "Add it; the path in the finding names the message."),
    "E122": ("A required string field is empty.", "Give it a real value."),
    "E124": ("skills is empty; the spec requires at least one skill.", "Declare at least one skill (spec 5.7)."),
    "E125": ("A field uses its snake_case proto spelling.", "JSON field names must be camelCase (spec 5.5); clients ignore the snake_case one."),
    "W201": ("The preferred interface is plain HTTP.", "Serve production cards over HTTPS."),
    "W202": ("A security scheme is declared but no requirement uses it.", "Add it to securityRequirements, or delete the scheme."),
    "W203": ("The description is very short.", "Routers and humans match on it; say what the agent does."),
    "W210": ("An unknown field looks like a typo of a real one and is ignored by clients.", "Rename it as suggested."),
    "W211": ("An input/output mode is not a media type.", "Use type/subtype such as text/plain."),
    "W212": ("The protocolBinding is not a standard one.", "Use JSONRPC, GRPC or HTTP+JSON, or document your custom binding."),
    "W213": ("A gRPC interface url is not host:port.", "Use hostname:port without a scheme."),
    "W215": ("The card was served with a non-JSON content type.", "Serve application/json."),
    "W216": ("An extension has no uri.", "Add the uri clients use to request it via A2A-Extensions."),
    "W217": ("A requirement's scope list has no 'list' member.", "Write {\"list\": [\"scope\"]}; as written no scopes are required."),
    "I205": ("Streaming is on but push notifications are not.", "Fine; clients behind SSE-blocking proxies must poll."),
    "I206": ("The version is not semver.", "Fine if intentional (date-based); semver enables card diff --semver."),
    "I207": ("securityRequirements uses the pre-1.0 OpenAPI shape.", "Migrate to {\"schemes\": ...}; see a2aops compat."),
    "I208": ("The card uses the v0.3 'security' field.", "Rename to securityRequirements in the v1.0 shape."),
    "I209": ("A custom protocolBinding is declared.", "Standard clients skip this interface; expected for custom bindings."),
    "I215": ("The card response has no Cache-Control header.", "Add one (spec 8.6.1 SHOULD) so clients and registries can cache safely."),
    "I216": ("The card response has no ETag header.", "Add one (spec 8.6.1 SHOULD) so clients can revalidate cheaply."),
    # ---- auth surface
    "E300": ("The card is not a JSON object.", "Fix the card first (see E001)."),
    "E301": ("An OIDC scheme has no openIdConnectUrl.", "Add the discovery URL."),
    "E302": ("openIdConnectUrl is not an absolute HTTPS URL.", "Use https://; plain HTTP is reported but never fetched."),
    "E303": ("The card's OIDC discovery document cannot be fetched.", "Fix the URL or the identity provider; the card advertises auth that does not resolve."),
    "E304": ("The discovery document is not a JSON object.", "Serve a standard OpenID configuration document."),
    "E305": ("The discovery document has no token_endpoint.", "Clients cannot finish the flow the card advertises; fix the provider config."),
    "E311": ("An OAuth2 scheme defines no flows.", "Add at least one flow."),
    "E312": ("An OAuth2 flow is not an object.", "Make the flow an object."),
    "E313": ("An OAuth2 flow declares no tokenUrl.", "Add the tokenUrl."),
    "E331": ("An API-key scheme lacks name or location.", "Declare name and in (header, query or cookie)."),
    "E340": ("A requirement entry is not an object.", "Use objects in securityRequirements."),
    "E341": ("A requirement names a scheme that is not declared.", "Declare it in securitySchemes or remove the requirement."),
    "E342": ("A security scheme is not an object.", "Make it an object."),
    "E345": ("A scheme's inner definition is not an object.", "Make it an object."),
    "I301": ("Informational auth note.", "No action needed."),
    "I321": ("Bearer auth without bearerFormat.", "Add bearerFormat (e.g. JWT) so clients know the token shape."),
    "W306": ("The discovery issuer does not match the discovery URL origin.", "Token validators may reject tokens; align issuer and URL."),
    "W307": ("A card-supplied URL was not fetched (SSRF guard, offline, or error).", "Expected for private addresses; use --allow-private only on your own dev stack."),
    "W343": ("A security scheme has an unrecognized shape; deep checks skipped.", "Use apiKeySecurityScheme, httpAuthSecurityScheme, oauth2SecurityScheme, openIdConnectSecurityScheme or mtlsSecurityScheme."),
    "W344": ("A scheme declares more than one kind.", "Declare exactly one kind per scheme."),
    # ---- security lint
    "S801": ("Invisible, bidi or control characters in card text.", "Remove them; they can hide instructions from reviewers while a model still reads them."),
    "S802": ("Card prose reads like an instruction to a model (heuristic).", "Card text is untrusted input to routers; rewrite as plain description."),
    "S803": ("Markup in card text that renderers may fetch or run.", "Remove HTML/script/image markup from prose."),
    "S804": ("A URL points at a loopback, private or metadata address.", "Public cards must not point clients at internal addresses."),
    "S805": ("An endpoint is on a different host than the one serving the card.", "Confirm it is intended; a hijacked card can redirect clients."),
    "S806": ("A very long prose field.", "Routers put card text into model context; long fields hide injected text. Shorten it."),
    "S807": ("A URL embeds credentials.", "Remove user:password@ and rotate the secret."),
    "S808": ("Secret-looking text in a public card.", "Remove and rotate it."),
    # ---- signatures
    "G901": ("The card has no signatures.", "Sign it (spec 8.4) if consumers should verify origin."),
    "G902": ("A signature verified against a trusted key.", "No action."),
    "G903": ("No signature verified with the keys you trusted.", "Check the key set, or the card was modified after signing."),
    "G904": ("The signature algorithm is unsupported here.", "a2aops verifies ES256/384 and RS256/384/512 only."),
    "G905": ("No trusted key matched this signature.", "Pass the right --jwks."),
    "G906": ("The jku URL was not followed.", "By design: jku is attacker input. Pass --trust-jku only for the card's own host."),
    "G907": ("A refused algorithm (none, HS*) or a key/alg mismatch.", "Re-sign with an asymmetric algorithm matching the key."),
    "G908": ("A malformed signature entry.", "Fix the protected/signature members."),
    "G909": ("Verified only under the SDK canonicalization, not the spec's.", "Strict verifiers elsewhere may reject; re-sign per spec 8.4.1."),
    # ---- tasks
    "T401": ("The removed v0.x 'unknown' task state was seen.", "Normalize at the client edge; v1.0 has no such state."),
    "T402": ("An unknown task state string.", "The agent violates the protocol vocabulary."),
    "T403": ("TASK_STATE_UNSPECIFIED on the wire.", "It is invalid in responses."),
    "T404": ("A task moved out of a terminal state.", "Terminal tasks are immutable."),
    "T405": ("INPUT_REQUIRED with no status message.", "The client cannot know what to provide; always include guidance."),
    "T410": ("Polling a task failed.", "Check the URL, binding and task id."),
    "T411": ("The task was still not terminal when polling timed out.", "Raise --timeout or check the agent."),
    # ---- diff
    "D500": ("One of the two cards is not a JSON object.", "Fix the input."),
    "D501": ("A supported interface was removed.", "Clients with the endpoint cached will fail; keep it or announce a major version."),
    "D502": ("A skill was removed.", "Callers routing to it fail; deprecate before removal."),
    "D503": ("A skill stopped accepting an input mode.", "Existing clients sending it are rejected."),
    "D504": ("A skill stopped producing an output mode.", "Clients expecting it break."),
    "D505": ("A default input mode was removed.", "Clients using it are rejected."),
    "D506": ("A capability was turned off.", "Clients relying on it break."),
    "D507": ("An extension became required.", "Clients that do not speak it are rejected."),
    "D508": ("The agent now requires authentication.", "Anonymous clients break."),
    "D509": ("An accepted auth alternative was removed.", "Clients authenticating that way break."),
    "D510": ("A skill now requires authentication.", "Anonymous callers of that skill break."),
    "D511": ("A skill's auth alternative was removed.", "Clients using it break."),
    "D601": ("The preferred interface changed.", "Clients take the first interface; reorder deliberately."),
    "D602": ("An interface's protocolVersion changed.", "Check clients support it."),
    "D603": ("A skill dropped tags.", "Tag-based routers may stop matching it."),
    "D604": ("A default output mode was removed.", "Clients expecting it may break."),
    "D605": ("Agent-level auth requirements were removed.", "Confirm this is intentional."),
    "D606": ("A security scheme's definition changed.", "URLs, flows or scopes differ; clients may need updating."),
    "D607": ("The card changed but version did not.", "Bump version so clients can tell."),
    "D608": ("Breaking changes without a major version bump.", "Bump the major version."),
    "D609": ("A skill's auth requirements were removed.", "Confirm this is intentional."),
    "D610": ("The version moved less than the changes need (--semver).", "Use the bump printed in the banner."),
    "D611": ("Versions are not semver, so the bump cannot be compared.", "Use semver or drop --enforce-semver."),
    "D701": ("An interface was added.", "Additive; no action."),
    "D702": ("A skill was added.", "Additive; no action."),
    "D703": ("A capability was enabled.", "Additive; no action."),
    "D704": ("An auth alternative was added.", "Additive; no action."),
    "D705": ("A skill gained an auth alternative.", "Additive; no action."),
}

#: Codes shared by the conformance suite are named like CARD-01 and explained by their own output.


def explain(code: str) -> str:
    key = code.strip().upper()
    if key in CODES:
        meaning, fix = CODES[key]
        return f"{key}\n  meaning: {meaning}\n  fix:     {fix}"
    near = sorted(c for c in CODES if c.startswith(key[:2]) and key[:1].isalpha())[:8]
    hint = f" Did you mean one of: {', '.join(near)}?" if near else ""
    return f"unknown code {code!r}.{hint}"
