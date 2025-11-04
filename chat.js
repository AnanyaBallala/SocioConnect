let socket = null;
let currentChatUserId = null;
let currentChatUsername = null;

// Initialize socket connection when dashboard loads
document.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('token');
    if (token && window.location.pathname.includes('dashboard.html')) {
        initializeSocket();
        setupChatHandlers();
    }
});

function initializeSocket() {
    const token = localStorage.getItem('token');
    
    socket = io({
        auth: {
            token: token
        }
    });

    socket.on('connect', () => {
        console.log('Connected to chat server');
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from chat server');
    });

    socket.on('new_message', (data) => {
        if (data.sender_id === currentChatUserId) {
            displayMessage(data, false);
            scrollToBottom();
        }
    });

    socket.on('user_online', (userId) => {
        updateUserStatus(userId, 'online');
    });

    socket.on('user_offline', (userId) => {
        updateUserStatus(userId, 'offline');
    });

    socket.on('error', (error) => {
        console.error('Socket error:', error);
        showError('Chat connection error: ' + error.message);
    });
}

function setupChatHandlers() {
    const messageInput = document.getElementById('messageInput');
    const sendMessageBtn = document.getElementById('sendMessageBtn');
    const closeChatBtn = document.getElementById('closeChatBtn');

    if (messageInput) {
        messageInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    if (sendMessageBtn) {
        sendMessageBtn.addEventListener('click', sendMessage);
    }

    if (closeChatBtn) {
        closeChatBtn.addEventListener('click', closeChat);
    }
}

async function openChat(userId, username) {
    currentChatUserId = userId;
    currentChatUsername = username;

    // Update chat header
    document.getElementById('chatUsername').textContent = username;
    document.getElementById('chatStatus').textContent = 'online';

    // Enable chat input
    const messageInput = document.getElementById('messageInput');
    const sendMessageBtn = document.getElementById('sendMessageBtn');
    
    messageInput.disabled = false;
    sendMessageBtn.disabled = false;
    messageInput.placeholder = `Type a message to ${username}...`;

    // Show chat panel
    document.getElementById('chatPanel').classList.add('active');

    // Load chat history
    await loadChatHistory(userId);

    // Join chat room
    if (socket) {
        socket.emit('join_chat', { friendId: userId });
    }

    // Focus on input
    messageInput.focus();
}

function closeChat() {
    // Leave chat room
    if (socket && currentChatUserId) {
        socket.emit('leave_chat', { friendId: currentChatUserId });
    }

    // Reset chat state
    currentChatUserId = null;
    currentChatUsername = null;

    // Hide chat panel
    document.getElementById('chatPanel').classList.remove('active');

    // Disable chat input
    const messageInput = document.getElementById('messageInput');
    const sendMessageBtn = document.getElementById('sendMessageBtn');
    
    messageInput.disabled = true;
    sendMessageBtn.disabled = true;
    messageInput.value = '';
    messageInput.placeholder = 'Select a friend to chat...';

    // Clear messages
    document.getElementById('chatMessages').innerHTML = '';

    // Reset header
    document.getElementById('chatUsername').textContent = 'Select a friend to chat';
    document.getElementById('chatStatus').textContent = 'offline';
}

async function loadChatHistory(userId) {
    try {
        showLoading();
        const response = await makeAuthenticatedRequest(`/api/messages/${userId}`);
        
        if (response.ok) {
            const messages = await response.json();
            displayChatHistory(messages);
        } else {
            throw new Error('Failed to load chat history');
        }
    } catch (error) {
        console.error('Error loading chat history:', error);
        showError('Failed to load chat history');
    } finally {
        hideLoading();
    }
}

function displayChatHistory(messages) {
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.innerHTML = '';

    messages.forEach(message => {
        displayMessage(message, message.sender_id !== currentChatUserId);
    });

    scrollToBottom();
}

function displayMessage(message, isSent) {
    const chatMessages = document.getElementById('chatMessages');
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isSent ? 'sent' : 'received'}`;
    
    const messageTime = new Date(message.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
    });

    messageElement.innerHTML = `
        <div class="message-text">${escapeHtml(message.message)}</div>
        <div class="message-time">${messageTime}</div>
    `;

    chatMessages.appendChild(messageElement);
}

async function sendMessage() {
    const messageInput = document.getElementById('messageInput');
    const messageText = messageInput.value.trim();

    if (!messageText || !currentChatUserId) {
        return;
    }

    try {
        const response = await makeAuthenticatedRequest('/api/messages', {
            method: 'POST',
            body: JSON.stringify({
                receiverId: currentChatUserId,
                message: messageText
            })
        });

        if (response.ok) {
            const messageData = await response.json();
            
            // Display message immediately
            displayMessage({
                message: messageText,
                timestamp: new Date().toISOString(),
                sender_id: 'current_user'
            }, true);

            // Emit to socket for real-time delivery
            if (socket) {
                socket.emit('send_message', {
                    receiverId: currentChatUserId,
                    message: messageText,
                    messageId: messageData.id
                });
            }

            // Clear input
            messageInput.value = '';
            scrollToBottom();
        } else {
            throw new Error('Failed to send message');
        }
    } catch (error) {
        console.error('Error sending message:', error);
        showError('Failed to send message');
    }
}

function scrollToBottom() {
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function updateUserStatus(userId, status) {
    if (userId === currentChatUserId) {
        document.getElementById('chatStatus').textContent = status;
        
        // Update status color
        const statusElement = document.getElementById('chatStatus');
        statusElement.className = `chat-status ${status}`;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Cleanup socket connection when leaving the page
window.addEventListener('beforeunload', function() {
    if (socket) {
        socket.disconnect();
    }
});

// Export functions for global use
window.openChat = openChat;
window.closeChat = closeChat;