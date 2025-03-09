const urls = {
    'rgst_begin':  "/register/begin",
    'rgst_finish': "/register/finish",
    'auth_begin':  "/authenticate/begin",
    'auth_finish': "/authenticate/finish",
    'users':       "/users",
};
const registerButton = document.getElementById("register");
const loginButton = document.getElementById("authenticate");
const getusers = document.getElementById("getusers");

// Base64文字列をArrayBufferにデコード
function base64ToArrayBuffer(base64String) {
    return Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
}

registerButton.addEventListener("click", async () => {
    try {
        const username = document.getElementById('username').value;
        json = {'username': username};
        const response = await fetch(urls['rgst_begin'], {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(json),
        });
        const options = await response.json();
        // JavaScript 側でArrayBufferに変換
        options.user.id = base64ToArrayBuffer(options.user.id);
        options.challenge = base64ToArrayBuffer(options.challenge);
        // console.log(JSON.stringify(options, null, 2));
        const attResp = await navigator.credentials.create(
            { publicKey: options }
        );
        await fetch(urls['rgst_finish'], {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(attResp)
        });
        alert("Registration successful!");
    } catch (err) {
        console.error("Registration failed", err);
        alert("Registration failed");
    }
});

loginButton.addEventListener("click", async () => {
    try {
        const response = await fetch(urls['auth_begin'], {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const options = await response.json();
        // JavaScript 側でArrayBufferに変換
        options.challenge = base64ToArrayBuffer(options.challenge);
        // console.log(JSON.stringify(options, null, 2));
        const assertionResp = await navigator.credentials.get(
            { publicKey: options }
        );
        // const assertionResp = await startAuthentication(options);
        await fetch(urls['auth_finish'], {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(assertionResp)
        });
        alert("Authentication successful!");
    } catch (err) {
        console.error("Authentication failed", err);
        alert("Authentication failed");
    }
});

getusers.addEventListener("click", async () => {
    try {
        const resp = await fetch(urls['users'], {
            method: "GET",
            headers: { "Content-Type": "application/json" }
        });
        const users = await resp.json();
        const users_field = document.getElementById('users');
        users_field.textContent = JSON.stringify(users, null, 2);
    } catch (err) {
        alert("Users failed");
    }
});

// https://azukiazusa.dev/blog/implement-path-key-in-browser/
// 条件付きUI に対応しているかどうか. 対応していれば true が返る
async function isCMA() {
    if (
        typeof window.PublicKeyCredential !== "undefined" &&
        typeof window.PublicKeyCredential.isConditionalMediationAvailable === "function"
    ) {
        const available = await PublicKeyCredential.isConditionalMediationAvailable();
        return available;
    }
}

// パスキーを作成して認証できる環境かどうか. 認証できれば ture が返る
function isPlatformAuthenticatorAvailable() {
    if (
        typeof window.PublicKeyCredential !== "undefined" &&
        typeof window.PublicKeyCredential
            .isUserVerifyingPlatformAuthenticatorAvailable === "function"
    ) {
        return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
}
