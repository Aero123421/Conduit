(() => {
  const fromBase64url = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4)), (character) => character.charCodeAt(0));
  const toBase64url = (value) => {
    if (value === null) return null;
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const csrf = () => document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("__Host-conduit_csrf="))?.slice("__Host-conduit_csrf=".length) ?? "";
  const assertion = async (options) => {
    const publicKey = { ...options, challenge: fromBase64url(options.challenge), allowCredentials: (options.allowCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })) };
    const credential = await navigator.credentials.get({ publicKey });
    if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser did not return a passkey credential");
    const response = credential.response;
    return { id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { clientDataJSON: toBase64url(response.clientDataJSON), authenticatorData: toBase64url(response.authenticatorData), signature: toBase64url(response.signature), userHandle: toBase64url(response.userHandle) } };
  };
  const registration = async (options) => {
    const publicKey = { ...options, challenge: fromBase64url(options.challenge), user: { ...options.user, id: fromBase64url(options.user.id) }, excludeCredentials: (options.excludeCredentials ?? []).map((item) => ({ ...item, id: fromBase64url(item.id) })) };
    const credential = await navigator.credentials.create({ publicKey });
    if (!(credential instanceof PublicKeyCredential)) throw new Error("The browser did not return a passkey credential");
    const response = credential.response;
    return { id: credential.id, rawId: toBase64url(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(), response: { clientDataJSON: toBase64url(response.clientDataJSON), attestationObject: toBase64url(response.attestationObject), transports: typeof response.getTransports === "function" ? response.getTransports() : [] } };
  };
  const post = async (path, body, withCsrf) => {
    const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json", ...(withCsrf ? { "x-csrf-token": csrf() } : {}) }, body: JSON.stringify(body) });
    const value = await response.json();
    if (!response.ok) throw new Error(value?.error?.message ?? "Passkey request failed");
    return value;
  };
  const run = async (stepUp) => {
    const optionsPath = stepUp ? "/api/v1/auth/step-up/options" : "/api/v1/auth/login/options";
    const verifyPath = stepUp ? "/api/v1/auth/step-up/verify" : "/api/v1/auth/login/verify";
    const ceremony = await post(optionsPath, {}, stepUp);
    await post(verifyPath, { challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, response: await assertion(ceremony.options) }, stepUp);
  };
  document.querySelector("#passkey-setup")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.querySelector("#passkey-setup-submit");
    const status = document.querySelector("#auth-status");
    const displayName = document.querySelector("#setup-display-name")?.value ?? "Owner";
    const bootstrapSecret = document.querySelector("#setup-bootstrap-secret")?.value ?? "";
    const label = document.querySelector("#setup-passkey-label")?.value ?? "Owner passkey";
    try {
      button.disabled = true;
      if (status) status.textContent = "Waiting for a new passkey…";
      const ceremony = await post("/api/v1/auth/setup/options", { displayName, bootstrapSecret }, false);
      const response = await registration(ceremony.options);
      await post("/api/v1/auth/setup/verify", { challengeId: ceremony.challengeId, challenge: ceremony.options.challenge, response, displayName, bootstrapSecret, label, transports: response.response.transports ?? [] }, false);
      location.assign("/");
    } catch (error) {
      button.disabled = false;
      if (status) status.textContent = error instanceof Error ? error.message : "Passkey setup failed";
    }
  });
  document.querySelector("#passkey-sign-in")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const status = document.querySelector("#auth-status");
    try {
      button.disabled = true;
      if (status) status.textContent = "Waiting for passkey…";
      await run(false);
      const candidate = new URL(location.href).searchParams.get("return_to");
      const target = candidate === null ? "/" : new URL(candidate, location.origin);
      location.assign(target.origin === location.origin && target.pathname === "/authorize" ? `${target.pathname}${target.search}` : "/");
    } catch (error) {
      button.disabled = false;
      if (status) status.textContent = error instanceof Error ? error.message : "Passkey sign-in failed";
    }
  });
  document.querySelector("#oauth-step-up")?.addEventListener("click", async () => {
    const button = document.querySelector("#oauth-step-up");
    const status = document.querySelector("#oauth-status");
    try { button.disabled = true; if (status) status.textContent = "Waiting for passkey…"; await run(true); location.reload(); }
    catch (error) { button.disabled = false; if (status) status.textContent = error instanceof Error ? error.message : "Passkey verification failed"; }
  });
})();
