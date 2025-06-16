const ws = new WebSocket('ws://///');
let currentUser = '';

ws.onmessage = (event) => {
    const chatBox = document.getElementById('chat-box');
    chatBox.innerHTML += `<p>${event.data}</p>`;
};

function showRegister() {
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('register-page').style.display = 'block';
}

function showLogin() {
    document.getElementById('register-page').style.display = 'none';
    document.getElementById('login-page').style.display = 'block';
}

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('////', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    }).then(res => res.json()).then(data => {
        if (data.success) {
            currentUser = username;
            document.getElementById('login-page').style.display = 'none';
            document.getElementById('chat-page').style.display = 'block';
        } else {
            alert('Invalid login');
        }
    });
}

function register() {
    const username = document.getElementById('reg-username').value;
    const password = document.getElementById('reg-password').value;

    fetch('///////', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    }).then(res => res.json()).then(data => {
        if (data.success) {
            showLogin();
        } else {
            alert('Registration failed');
        }
    });
}

function sendMessage() {
    const message = document.getElementById('message').value;
    ws.send(`${currentUser}: ${message}`);
    document.getElementById('message').value = '';
}

function logout() {
    currentUser = '';
    showLogin();
}
