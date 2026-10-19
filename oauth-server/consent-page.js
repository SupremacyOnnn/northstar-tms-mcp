
export function renderConsentPage(uid, clientId, csrfToken) {
  const safeUid = encodeURIComponent(uid);

  const escapeHtml = (value) =>
    String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[char]);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Northstar TMS Authorization</title>
</head>
<body style="font-family:Arial;max-width:460px;margin:80px auto;line-height:1.6">
  <h2>Northstar TMS Authorization</h2>
  <p><strong>${escapeHtml(clientId)}</strong> is requesting access to Northstar TMS.</p>

<h3>Requested permissions</h3>

<p><strong>Authentication</strong></p>
<p>Verify your identity using your Northstar TMS account.</p>

<p><strong>Shipment tracking — Read Only</strong></p>
<p>
  View shipment status and tracking events for loads
  you are authorized to access.
</p>

<p>Permission: <strong>northstar:loads:read</strong></p>
<p>Resource: <strong>Northstar MCP Server</strong></p>

<p>
  You will only be able to access shipments permitted
  by your existing Northstar TMS role and access rights.
</p>
  <p>Requested permission: <strong>openid</strong></p>

  <form method="POST" action="/interaction/${safeUid}/consent">
    <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">

    <button type="submit" name="decision" value="allow">
      Allow
    </button>

    <button type="submit" name="decision" value="deny">
      Deny
    </button>
  </form>
</body>
</html>`;
}
