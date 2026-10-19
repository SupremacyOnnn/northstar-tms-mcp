
export function renderLoginPage(uid, error = "", csrfToken = "") {
  if (!uid || !csrfToken) {
    throw new Error("OAuth interaction UID and CSRF token are required");
  }

  const safeUid = encodeURIComponent(uid);

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width, initial-scale=1.0">

  <title>Northstar TMS Login</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      font-family: Arial, sans-serif;
      background: #f3f6fa;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }

    .login-box {
      background: white;
      padding: 35px;
      border-radius: 12px;
      width: 360px;
      max-width: 90vw;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    }

    h2 {
      text-align: center;
      color: #17365d;
      margin-bottom: 8px;
    }

    .subtitle {
      text-align: center;
      color: #666;
      font-size: 14px;
      margin-bottom: 25px;
    }

    label {
      display: block;
      margin-top: 15px;
      margin-bottom: 6px;
      font-weight: bold;
    }

    input {
      width: 100%;
      padding: 11px;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-size: 15px;
    }

    input:focus {
      outline: 2px solid #17365d;
      outline-offset: 1px;
    }

    button {
      width: 100%;
      margin-top: 25px;
      padding: 12px;
      background: #17365d;
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 16px;
      cursor: pointer;
    }

    button:hover {
      background: #244b7c;
    }

    .error {
      color: #b42318;
      text-align: center;
      font-size: 14px;
      margin-bottom: 15px;
    }
  </style>
</head>

<body>
  <div class="login-box">

    <h2>Northstar TMS</h2>
    <p class="subtitle">Secure Employee Login</p>

    ${
      error
        ? '<p class="error" role="alert">Invalid User ID or password</p>'
        : ""
    }

    <form
      method="POST"
      action="/interaction/${safeUid}/login"
      autocomplete="on"
    >

      <input
        type="hidden"
        name="_csrf"
        value="${csrfToken}"
      >

      <label for="user_id">User ID</label>
      <input
        type="text"
        id="user_id"
        name="user_id"
        placeholder="Enter your User ID"
        autocomplete="username"
        maxlength="100"
        required
      >

      <label for="password">Password</label>
      <input
        type="password"
        id="password"
        name="password"
        placeholder="Enter your password"
        autocomplete="current-password"
        required
      >

      <button type="submit">
        Sign In
      </button>

    </form>

  </div>
</body>
</html>
`;
}
