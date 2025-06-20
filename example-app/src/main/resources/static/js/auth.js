/**
 * Common authentication functions for JWT Authentication Demo
 */


// Function to check if user is authenticated
function isAuthenticated() {
    return sessionStorage.getItem('jwt_token') !== null;
}

// Function to get the JWT token
function getToken() {
    return sessionStorage.getItem('jwt_token');
}

// Function to set the JWT token
function setToken(token) {
    sessionStorage.setItem('jwt_token', token);
}

// Function to remove the JWT token
function removeToken() {
    sessionStorage.removeItem('jwt_token');
}

function authHeader() {
    const token = getToken();
    return token ? {'Authorization': `Bearer ${token}`} : {};
}

// Function to handle registration
function register(username, email, password) {
    return fetch('/api/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            email: email,
            password: password
        })
    })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || 'Registration failed');
                });
            }
            return response.json();
        });
}

function authenticatedFetch(url, options = {}) {
    const token = getToken();

    if (!token) {
        return Promise.reject(new Error('No authentication token'));
    }

    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
        }
    };

    return fetch(url, {...options, ...defaultOptions})
        .then(response => {
            if (response.status === 401) {
                // Token expired or invalid
                removeToken();
                window.location.href = '/login';
                throw new Error('Authentication expired');
            }
            return response;
        });
}

// Function to handle login
function login(username, password) {
    return fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Login failed');
            }
            return response.json();
        })
        .then(data => {
            setToken(data.token);
            console.log("Login successful. Token stored.");
            console.log(data);
            return data;
        });
}

// Function to handle logout
function logout() {
    const token = getToken();

    if (!token) {
        return Promise.reject(new Error('No token found'));
    }

    return fetch('/api/auth/logout', {
        method: 'POST',
        headers: authHeader()
    })
        .then(response => {
            removeToken();
            return response;
        });
}



