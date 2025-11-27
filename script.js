document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    const token = localStorage.getItem('token');
    if (token && window.location.pathname.includes('index.html')) {
        // Verify token is still valid
        verifyToken(token);
    }

    // Form switching
    const showRegisterBtn = document.getElementById('showRegister');
    const showLoginBtn = document.getElementById('showLogin');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    if (showRegisterBtn) {
        showRegisterBtn.addEventListener('click', function(e) {
            e.preventDefault();
            loginForm.classList.remove('active');
            registerForm.classList.add('active');
        });
    }

    if (showLoginBtn) {
        showLoginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            registerForm.classList.remove('active');
            loginForm.classList.add('active');
        });
    }

    // Form submissions
    const loginFormElement = document.getElementById('loginFormElement');
    const registerFormElement = document.getElementById('registerFormElement');

    if (loginFormElement) {
        loginFormElement.addEventListener('submit', handleLogin);
    }

    if (registerFormElement) {
        registerFormElement.addEventListener('submit', handleRegister);
    }

    // Modal close functionality
    setupModalHandlers();
});

async function verifyToken(token) {
    try {
        const response = await fetch('/api/verify-token', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            window.location.href = 'dashboard.html';
        } else {
            localStorage.removeItem('token');
        }
    } catch (error) {
        console.error('Token verification failed:', error);
        localStorage.removeItem('token');
    }
}

async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
        showError('Please fill in all fields');
        return;
    }

    showLoading();

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            window.location.href = 'dashboard.html';
        } else {
            throw new Error(data.message || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError(error.message || 'Login failed. Please try again.');
    } finally {
        hideLoading();
    }
}

async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const location = document.getElementById('registerLocation').value;
    const interests = document.getElementById('registerInterests').value;

    if (!username || !email || !password || !location || !interests) {
        showError('Please fill in all fields');
        return;
    }

    if (password.length < 6) {
        showError('Password must be at least 6 characters long');
        return;
    }

    if (!isValidEmail(email)) {
        showError('Please enter a valid email address');
        return;
    }

    showLoading();

    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                email,
                password,
                location,
                interests
            })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            window.location.href = 'dashboard.html';
        } else {
            throw new Error(data.message || 'Registration failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showError(error.message || 'Registration failed. Please try again.');
    } finally {
        hideLoading();
    }
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'flex';
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

function showError(message) {
    const errorModal = document.getElementById('errorModal');
    const errorMessage = document.getElementById('errorMessage');
    
    if (errorModal && errorMessage) {
        errorMessage.textContent = message;
        errorModal.style.display = 'block';
    } else {
        alert(message); // Fallback
    }
}

function setupModalHandlers() {
    // Close button handlers
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener('click', function() {
            this.closest('.modal').style.display = 'none';
        });
    });

    // Click outside modal to close
    window.addEventListener('click', function(e) {
        if (e.target.classList.contains('modal')) {
            e.target.style.display = 'none';
        }
    });

    // Escape key to close modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(modal => {
                modal.style.display = 'none';
            });
        }
    });
}

// Utility functions for API calls
async function makeAuthenticatedRequest(url, options = {}) {
    const token = localStorage.getItem('token');
    
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        }
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };

    try {
        const response = await fetch(url, mergedOptions);
        
        if (response.status === 401) {
            localStorage.removeItem('token');
            window.location.href = 'index.html';
            return;
        }

        return response;
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}

// Export functions for use in dashboard
window.makeAuthenticatedRequest = makeAuthenticatedRequest;
window.showError = showError;
window.showLoading = showLoading;
window.hideLoading = hideLoading;