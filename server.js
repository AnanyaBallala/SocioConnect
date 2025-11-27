const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());
 app.use(express.static(path.join(__dirname)));
//app.use(express.static("public"));


// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// In-memory database for demo purposes (replace with MySQL when available)
let users = [];
let friendships = [];
let messages = [];
let userIdCounter = 1;
let friendshipIdCounter = 1;
let messageIdCounter = 1;

// Initialize in-memory database with sample data
function initializeInMemoryDatabase() {
    console.log('Using in-memory database for demo purposes');
    console.log('Note: Data will be lost when server restarts');
    
    // Add sample users for testing
    const sampleUsers = [
        {
            id: userIdCounter++,
            username: 'john_doe',
            email: 'john@example.com',
            password: bcrypt.hashSync('password123', 10),
            location: 'New York',
            interests: 'music, sports, technology',
            created_at: new Date()
        },
        {
            id: userIdCounter++,
            username: 'jane_smith',
            email: 'jane@example.com',
            password: bcrypt.hashSync('password123', 10),
            location: 'New York',
            interests: 'art, music, photography',
            created_at: new Date()
        },
        {
            id: userIdCounter++,
            username: 'mike_wilson',
            email: 'mike@example.com',
            password: bcrypt.hashSync('password123', 10),
            location: 'Los Angeles',
            interests: 'sports, fitness, travel',
            created_at: new Date()
        }
    ];
    
    users.push(...sampleUsers);
    console.log('Sample users created for testing');
}

// Helper functions for in-memory database operations
function findUserByEmail(email) {
    return users.find(user => user.email === email);
}

function findUserByUsername(username) {
    return users.find(user => user.username === username);
}

function findUserById(id) {
    return users.find(user => user.id === parseInt(id));
}

function createUser(userData) {
    const newUser = {
        id: userIdCounter++,
        ...userData,
        created_at: new Date()
    };
    users.push(newUser);
    return newUser;
}

function updateUser(userId, updateData) {
    const userIndex = users.findIndex(user => user.id === parseInt(userId));
    if (userIndex !== -1) {
        users[userIndex] = { ...users[userIndex], ...updateData };
        return users[userIndex];
    }
    return null;
}

function findFriendship(user1Id, user2Id) {
    return friendships.find(f => 
        (f.user1_id === parseInt(user1Id) && f.user2_id === parseInt(user2Id)) ||
        (f.user1_id === parseInt(user2Id) && f.user2_id === parseInt(user1Id))
    );
}

function createFriendship(user1Id, user2Id, status = 'accepted') {
    const friendship = {
        id: friendshipIdCounter++,
        user1_id: parseInt(user1Id),
        user2_id: parseInt(user2Id),
        status: status,
        created_at: new Date()
    };
    friendships.push(friendship);
    return friendship;
}

function getUserFriends(userId) {
    const userFriendships = friendships.filter(f => 
        (f.user1_id === parseInt(userId) || f.user2_id === parseInt(userId)) && 
        f.status === 'accepted'
    );
    
    return userFriendships.map(f => {
        const friendId = f.user1_id === parseInt(userId) ? f.user2_id : f.user1_id;
        return findUserById(friendId);
    }).filter(Boolean);
}

function createMessage(senderId, receiverId, messageText) {
    const message = {
        id: messageIdCounter++,
        sender_id: parseInt(senderId),
        receiver_id: parseInt(receiverId),
        message: messageText,
        timestamp: new Date()
    };
    messages.push(message);
    return message;
}

function getMessages(user1Id, user2Id) {
    return messages.filter(m => 
        (m.sender_id === parseInt(user1Id) && m.receiver_id === parseInt(user2Id)) ||
        (m.sender_id === parseInt(user2Id) && m.receiver_id === parseInt(user1Id))
    ).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, location, interests } = req.body;

        // Validation
        if (!username || !email || !password || !location || !interests) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Check if user already exists
        if (findUserByEmail(email) || findUserByUsername(username)) {
            return res.status(400).json({ message: 'User with this email or username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = createUser({
            username,
            email,
            password: hashedPassword,
            location,
            interests
        });

        // Generate JWT token
        const token = jwt.sign(
            { userId: newUser.id, username, email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: { id: newUser.id, username, email, location, interests }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find user
        const user = findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                location: user.location,
                interests: user.interests
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Verify Token
app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ message: 'Token is valid', user: req.user });
});

// Get User Profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = findUserById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const { password, ...userProfile } = user;
        res.json(userProfile);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update User Profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { location, interests } = req.body;

        if (!location || !interests) {
            return res.status(400).json({ message: 'Location and interests are required' });
        }

        const updatedUser = updateUser(req.user.userId, { location, interests });
        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Find Nearby Users with Similar Interests
app.get('/api/users/nearby', authenticateToken, async (req, res) => {
    try {
        const currentUser = findUserById(req.user.userId);
        if (!currentUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        const userLocation = currentUser.location.toLowerCase();
        const userInterests = currentUser.interests.toLowerCase().split(',').map(i => i.trim());

        // Find users in the same location who are not already friends
        const nearbyUsers = users.filter(user => {
            if (user.id === currentUser.id) return false;
            if (user.location.toLowerCase() !== userLocation) return false;
            
            // Check if already friends
            const existingFriendship = findFriendship(currentUser.id, user.id);
            if (existingFriendship) return false;
            
            return true;
        });

        // Score users based on common interests
        const scoredUsers = nearbyUsers.map(user => {
            const otherInterests = user.interests.toLowerCase().split(',').map(i => i.trim());
            const commonInterests = userInterests.filter(interest => 
                otherInterests.some(otherInterest => 
                    otherInterest.includes(interest) || interest.includes(otherInterest)
                )
            );
            
            const { password, ...userWithoutPassword } = user;
            return {
                ...userWithoutPassword,
                commonInterests: commonInterests.length,
                score: commonInterests.length
            };
        });

        // Sort by score (most common interests first)
        scoredUsers.sort((a, b) => b.score - a.score);

        res.json(scoredUsers.slice(0, 10)); // Return top 10 matches
    } catch (error) {
        console.error('Nearby users fetch error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Send Friend Request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.body;

        if (!friendId) {
            return res.status(400).json({ message: 'Friend ID is required' });
        }

        if (parseInt(friendId) === req.user.userId) {
            return res.status(400).json({ message: 'Cannot send friend request to yourself' });
        }

        // Check if friendship already exists
        const existingFriendship = findFriendship(req.user.userId, friendId);
        if (existingFriendship) {
            return res.status(400).json({ message: 'Friendship already exists or request already sent' });
        }

        // Create friendship (auto-accept for simplicity in this demo)
        createFriendship(req.user.userId, friendId, 'accepted');

        res.json({ message: 'Friend request sent and accepted successfully' });
    } catch (error) {
        console.error('Friend request error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get User's Friends
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const friends = getUserFriends(req.user.userId);
        const friendsWithoutPasswords = friends.map(friend => {
            const { password, ...friendWithoutPassword } = friend;
            return friendWithoutPassword;
        });
        
        res.json(friendsWithoutPasswords);
    } catch (error) {
        console.error('Friends fetch error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get Messages with a Friend
app.get('/api/messages/:friendId', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.params;

        // Verify friendship exists
        const friendship = findFriendship(req.user.userId, friendId);
        if (!friendship || friendship.status !== 'accepted') {
            return res.status(403).json({ message: 'Not friends with this user' });
        }

        // Get messages
        const chatMessages = getMessages(req.user.userId, friendId);
        
        // Add sender username to messages
        const messagesWithSender = chatMessages.map(msg => {
            const sender = findUserById(msg.sender_id);
            return {
                ...msg,
                sender_username: sender ? sender.username : 'Unknown'
            };
        });

        res.json(messagesWithSender);
    } catch (error) {
        console.error('Messages fetch error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Send Message
// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { receiverId, message } = req.body;

        if (!receiverId || !message) {
            return res.status(400).json({ message: 'Receiver ID and message are required' });
        }

        // Verify friendship exists
        const friendship = findFriendship(req.user.userId, receiverId);
        if (!friendship || friendship.status !== 'accepted') {
            return res.status(403).json({ message: 'Not friends with this user' });
        }

        // Create message
        const newMessage = createMessage(req.user.userId, receiverId, message);

        // Return full message details
        res.json({
            id: newMessage.id,
            sender_id: newMessage.sender_id,
            receiver_id: newMessage.receiver_id,
            message: newMessage.message,
            timestamp: newMessage.timestamp
        });
    } catch (error) {
        console.error('Message send error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Socket.io for real-time chat
const connectedUsers = new Map();

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        socket.username = decoded.username;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log(`User ${socket.username} connected`);
    connectedUsers.set(socket.userId, socket.id);

    // Notify friends that user is online
    socket.broadcast.emit('user_online', socket.userId);

    socket.on('join_chat', ({ friendId }) => {
        const chatRoom = [socket.userId, parseInt(friendId)].sort().join('-');
        socket.join(chatRoom);
        console.log(`User ${socket.username} joined chat room ${chatRoom}`);
    });

    socket.on('leave_chat', ({ friendId }) => {
        const chatRoom = [socket.userId, parseInt(friendId)].sort().join('-');
        socket.leave(chatRoom);
        console.log(`User ${socket.username} left chat room ${chatRoom}`);
    });

    socket.on('send_message', async ({ receiverId, message, messageId }) => {
        try {
            const chatRoom = [socket.userId, parseInt(receiverId)].sort().join('-');
            
            // Emit to the chat room
            socket.to(chatRoom).emit('new_message', {
                id: messageId,
                sender_id: socket.userId,
                sender_username: socket.username,
                message: message,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            console.error('Socket message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    socket.on('disconnect', () => {
        console.log(`User ${socket.username} disconnected`);
        connectedUsers.delete(socket.userId);
        
        // Notify friends that user is offline
        socket.broadcast.emit('user_offline', socket.userId);
    });
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Start server
const PORT = process.env.PORT || 3000;

async function startServer() {
    // Initialize in-memory database
    initializeInMemoryDatabase();
    
    server.listen(PORT, () => {
        console.log(`🚀 SocioConnect server running on http://localhost:${PORT}`);
        console.log('📝 Using in-memory database (data will be lost on restart)');
        console.log('👤 Sample users available:');
        console.log('   - john@example.com / password123');
        console.log('   - jane@example.com / password123');
        console.log('   - mike@example.com / password123');
        console.log('✅ Server is ready for connections!');
    });
}

startServer().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
});