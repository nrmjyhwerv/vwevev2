const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const WebSocket = require('ws');
const axios = require('axios');
const { sendPasswordResetEmail } = require('../handlers/email.js');
const { logAudit } = require('../handlers/auditlog');
const { db } = require('../handlers/db.js');

const saltRounds = 10;

// Improved API key validation middleware
async function validateApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
        return res.status(401).json({ error: 'API key is required' });
    }

    try {
        const apiKeys = await db.get('apiKeys') || [];
        const validKey = apiKeys.find(key => key.key === apiKey);

        if (!validKey) {
            return res.status(401).json({ error: 'Invalid API key' });
        }

        // Check if API key is expired
        if (validKey.expiresAt && new Date(validKey.expiresAt) < new Date()) {
            return res.status(401).json({ error: 'API key has expired' });
        }

        req.apiKey = validKey;
        next();
    } catch (error) {
        console.error('API key validation error:', error);
        res.status(500).json({ error: 'Failed to validate API key' });
    }
}

// Utility function for error responses
function errorResponse(res, status, message, error = null) {
    if (error) console.error(message, error);
    return res.status(status).json({ error: message });
}

// Users endpoints
router.get('/api/users', validateApiKey, async (req, res) => {
    try {
        const users = await db.get('users') || [];
        // Don't return password hashes
        const sanitizedUsers = users.map(user => {
            const { password, ...userData } = user;
            return userData;
        });
        res.json(sanitizedUsers);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve users', error);
    }
});

router.post('/api/getUser', validateApiKey, async (req, res) => {
    try {
        const { type, value } = req.body;

        if (!type || !value) {
            return errorResponse(res, 400, 'Type and value are required');
        }

        const users = await db.get('users') || [];
        let user;

        if (type === 'email') {
            user = users.find(user => user.email === value);
        } else if (type === 'username') {
            user = users.find(user => user.username === value);
        } else {
            return errorResponse(res, 400, 'Invalid search type. Use "email" or "username".');
        }

        if (!user) {
            return errorResponse(res, 404, 'User not found');
        }

        // Don't return password hash
        const { password, ...userData } = user;
        res.status(200).json(userData);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve user', error);
    }
});

router.post('/api/auth/create-user', validateApiKey, async (req, res) => {
    try {
        const { username, email, password, userId, admin } = req.body;

        if (!username || !email || !password) {
            return errorResponse(res, 400, 'Username, email and password are required');
        }

        // Validate email format
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return errorResponse(res, 400, 'Invalid email format');
        }

        // Validate password strength
        if (password.length < 8) {
            return errorResponse(res, 400, 'Password must be at least 8 characters');
        }

        const users = await db.get('users') || [];
        const userExists = users.some(user =>
            user.username === username || user.email === email
        );

        if (userExists) {
            return errorResponse(res, 409, 'User already exists');
        }

        const newUserId = userId || uuidv4();
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const user = {
            userId: newUserId,
            username,
            email,
            password: hashedPassword,
            accessTo: [],
            admin: admin === true || admin === 'true',
            createdAt: new Date().toISOString()
        };

        users.push(user);
        await db.set('users', users);

        // Don't return password hash
        const { password: _, ...userData } = user;
        res.status(201).json(userData);
    } catch (error) {
        errorResponse(res, 500, 'Failed to create user', error);
    }
});

router.post('/api/auth/reset-password', validateApiKey, async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return errorResponse(res, 400, 'Email is required');
    }

    try {
        const users = await db.get('users') || [];
        const user = users.find(u => u.email === email);

        if (!user) {
            // Don't reveal whether email exists for security
            return res.status(200).json({ message: 'If the email exists, a reset link has been sent' });
        }

        const resetToken = generateRandomCode(30);
        const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour expiry

        user.resetToken = resetToken;
        user.resetTokenExpiry = resetTokenExpiry.toISOString();
        await db.set('users', users);

        const smtpSettings = await db.get('smtp_settings');
        if (smtpSettings) {
            await sendPasswordResetEmail(email, resetToken);
            res.status(200).json({ message: 'Password reset email sent successfully' });
        } else {
            // In development, return the token for testing
            res.status(200).json({
                message: 'SMTP not configured - here is the reset token for testing',
                token: resetToken
            });
        }
    } catch (error) {
        errorResponse(res, 500, 'Failed to reset password', error);
    }
});

// Instance endpoints
router.get('/api/instances', validateApiKey, async (req, res) => {
    try {
        const instances = await db.get('instances') || [];
        res.status(200).json(instances);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve instances', error);
    }
});

router.ws("/api/instance/console/:id", async (ws, req) => {
    if (!req.user) {
        ws.close(1008, "Authorization required");
        return;
    }

    const { id } = req.params;
    if (!id) {
        ws.close(1008, "Instance ID required");
        return;
    }

    try {
        const instance = await db.get(id + '_instance');
        if (!instance) {
            ws.close(1008, "Instance not found");
            return;
        }

        const node = instance.Node;
        if (!node || !node.address || !node.port || !node.apiKey) {
            ws.close(1008, "Invalid node configuration");
            return;
        }

        const socket = new WebSocket(`ws://${node.address}:${node.port}/exec/${instance.ContainerId}`);

        socket.onopen = () => {
            socket.send(JSON.stringify({ "event": "auth", "args": [node.apiKey] }));
        };

        socket.onmessage = msg => {
            try {
                ws.send(msg.data);
            } catch (error) {
                console.error('WebSocket message send error:', error);
            }
        };

        socket.onerror = (error) => {
            ws.send('\x1b[31;1mCryptalis instance appears to be down');
            console.error('WebSocket error:', error);
        };

        socket.onclose = () => {
            ws.close();
        };

        ws.onmessage = msg => {
            try {
                socket.send(msg.data);
            } catch (error) {
                console.error('WebSocket message forward error:', error);
            }
        };

        ws.on('close', () => {
            socket.close();
        });

    } catch (error) {
        console.error('Console WebSocket error:', error);
        ws.close(1011, "Internal server error");
    }
});

router.post('/api/instances/deploy', validateApiKey, async (req, res) => {
    const { image, imagename, memory, cpu, disk, ports, nodeId, name, user, primary, variables } = req.body;

    // Validate required parameters
    const requiredParams = { image, memory, cpu, ports, nodeId, name, user, primary };
    const missingParams = Object.entries(requiredParams)
        .filter(([_, value]) => !value)
        .map(([key]) => key);

    if (missingParams.length > 0) {
        return errorResponse(res, 400, `Missing parameters: ${missingParams.join(', ')}`);
    }

    try {
        const Id = uuidv4().split('-')[0];
        const node = await db.get(`${nodeId}_node`);
        if (!node) {
            return errorResponse(res, 400, 'Invalid node');
        }

        if (!node.apiKey) {
            return errorResponse(res, 400, 'Node is not properly configured');
        }

        const requestData = await prepareRequestData(
            image,
            memory,
            cpu,
            ports,
            name,
            node,
            Id,
            variables,
            imagename
        );

        const response = await axios(requestData);

        if (response.status === 201) {
            await updateDatabaseWithNewInstance(
                response.data,
                user,
                node,
                image,
                memory,
                disk,
                cpu,
                ports,
                primary,
                name,
                Id,
                imagename
            );

            return res.status(201).json({
                message: "Deployment successful",
                containerId: response.data.containerId,
                volumeId: response.data.volumeId,
            });
        } else {
            return res.status(response.status).json({
                error: 'Failed to deploy container',
                details: response.data,
            });
        }
    } catch (error) {
        console.error('Deployment error:', error);
        const errorDetails = error.response ? {
            status: error.response.status,
            data: error.response.data
        } : error.message;

        errorResponse(res, 500, 'Failed to create container', errorDetails);
    }
});

router.delete('/api/instance/delete', validateApiKey, async (req, res) => {
    const { id } = req.body;

    if (!id) {
        return errorResponse(res, 400, 'Instance ID is required');
    }

    try {
        const instance = await db.get(id + '_instance');
        if (!instance) {
            return errorResponse(res, 404, 'Instance not found');
        }

        await deleteInstance(instance);
        res.status(200).json({ message: 'Instance successfully deleted' });
    } catch (error) {
        errorResponse(res, 500, 'Failed to delete instance', error);
    }
});

router.post('/api/instances/suspend', validateApiKey, async (req, res) => {
    const { id } = req.body;

    if (!id) {
        return errorResponse(res, 400, 'Instance ID is required');
    }

    try {
        const instance = await db.get(id + '_instance');
        if (!instance) {
            return errorResponse(res, 404, 'Instance not found');
        }

        instance.suspended = true;
        instance.suspendedAt = new Date().toISOString();
        await db.set(id + '_instance', instance);

        let instances = await db.get('instances') || [];
        const instanceToSuspend = instances.find(obj => obj.ContainerId === instance.ContainerId);
        if (instanceToSuspend) {
            instanceToSuspend.suspended = true;
            instanceToSuspend.suspendedAt = new Date().toISOString();
        }

        await db.set('instances', instances);

        res.status(200).json({
            success: true,
            message: `Instance ${id} has been suspended`
        });
    } catch (error) {
        errorResponse(res, 500, 'Failed to suspend instance', error);
    }
});

router.post('/api/instances/unsuspend', validateApiKey, async (req, res) => {
    const { id } = req.body;

    if (!id) {
        return errorResponse(res, 400, 'Instance ID is required');
    }

    try {
        const instance = await db.get(id + '_instance');
        if (!instance) {
            return errorResponse(res, 404, 'Instance not found');
        }

        instance.suspended = false;
        instance.unsuspendedAt = new Date().toISOString();
        await db.set(id + '_instance', instance);

        let instances = await db.get('instances') || [];
        const instanceToUnsuspend = instances.find(obj => obj.ContainerId === instance.ContainerId);
        if (instanceToUnsuspend) {
            instanceToUnsuspend.suspended = false;
            instanceToUnsuspend.unsuspendedAt = new Date().toISOString();
        }

        await db.set('instances', instances);

        logAudit(req.user.userId, req.user.username, 'instance:unsuspend', req.ip);

        res.status(200).json({
            success: true,
            message: `Instance ${id} has been unsuspended`
        });
    } catch (error) {
        errorResponse(res, 500, 'Failed to unsuspend instance', error);
    }
});

router.post('/api/getUserInstance', validateApiKey, async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return errorResponse(res, 400, 'User ID is required');
    }

    try {
        const userExists = await db.get('users').then(users =>
            users && users.some(user => user.userId === userId)
        );

        if (!userExists) {
            return errorResponse(res, 404, 'User not found');
        }

        const userInstances = await db.get(`${userId}_instances`) || [];
        res.json(userInstances);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve user instances', error);
    }
});

router.post('/api/getInstance', validateApiKey, async (req, res) => {
    const { id } = req.body;

    if (!id) {
        return errorResponse(res, 400, 'Instance ID is required');
    }

    try {
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return errorResponse(res, 404, 'Instance not found');
        }

        res.json(instance);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve instance', error);
    }
});

// Images endpoints
router.get('/api/images', validateApiKey, async (req, res) => {
    try {
        const images = await db.get('images') || [];
        res.json(images);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve images', error);
    }
});

// System endpoints
router.get('/api/name', validateApiKey, async (req, res) => {
    try {
        const name = await db.get('name') || 'HydraPanel';
        res.json({ name });
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve system name', error);
    }
});

// Nodes endpoints
router.get('/api/nodes', validateApiKey, async (req, res) => {
    try {
        const nodes = await db.get('nodes') || [];
        const nodeDetails = await Promise.all(nodes.map(async id => {
            const node = await db.get(id + '_node');
            return {
                id: node.id,
                name: node.name,
                status: node.status,
                tags: node.tags,
                address: node.address,
                port: node.port,
                versionFamily: node.versionFamily,
                versionRelease: node.versionRelease
            };
        }));
        res.json(nodeDetails);
    } catch (error) {
        errorResponse(res, 500, 'Failed to retrieve nodes', error);
    }
});

router.post('/api/nodes/create', validateApiKey, async (req, res) => {
    const { name, tags, ram, disk, processor, address, port } = req.body;

    if (!name || !tags || !ram || !disk || !processor || !address || !port) {
        return errorResponse(res, 400, 'All node parameters are required');
    }

    try {
        const configureKey = uuidv4();
        const node = {
            id: uuidv4(),
            name,
            tags,
            ram,
            disk,
            processor,
            address,
            port,
            apiKey: null,
            configureKey,
            status: 'Unconfigured',
            createdAt: new Date().toISOString()
        };

        await db.set(node.id + '_node', node);

        const nodes = await db.get('nodes') || [];
        nodes.push(node.id);
        await db.set('nodes', nodes);

        res.status(201).json({
            success: true,
            nodeId: node.id,
            configureKey
        });
    } catch (error) {
        errorResponse(res, 500, 'Failed to create node', error);
    }
});

router.delete('/api/nodes/delete/:id', validateApiKey, async (req, res) => {
    const nodeId = req.params.id;

    if (!nodeId) {
        return errorResponse(res, 400, 'Node ID is required');
    }

    try {
        // Check if node has instances
        const instances = await db.get('instances') || [];
        const nodeInstances = instances.filter(instance =>
            instance.Node && instance.Node.id === nodeId
        );

        if (nodeInstances.length > 0) {
            return errorResponse(res, 400, 'Cannot delete node with active instances');
        }

        const nodes = await db.get('nodes') || [];
        const newNodes = nodes.filter(id => id !== nodeId);
        await db.set('nodes', newNodes);
        await db.delete(nodeId + '_node');

        res.status(200).json({
            success: true,
            message: 'Node successfully deleted'
        });
    } catch (error) {
        errorResponse(res, 500, 'Failed to delete node', error);
    }
});

router.get('/api/nodes/configure-command', validateApiKey, async (req, res) => {
    const { id } = req.query;

    if (!id) {
        return errorResponse(res, 400, 'Node ID is required');
    }

    try {
        const node = await db.get(id + '_node');
        if (!node) {
            return errorResponse(res, 404, 'Node not found');
        }

        // Generate a new configure key
        const configureKey = uuidv4();
        node.configureKey = configureKey;
        await db.set(id + '_node', node);

        const panelUrl = `${req.protocol}://${req.get('host')}`;
        const configureCommand = `npm run configure -- --panel ${panelUrl} --key ${configureKey}`;

        res.json({
            nodeId: id,
            configureCommand
        });
    } catch (error) {
        errorResponse(res, 500, 'Failed to generate configure command', error);
    }
});

// Utility functions
function generateRandomCode(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let result = '';

    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

async function deleteInstance(instance) {
    try {
        // First try to delete the instance from the node
        await axios.delete(
            `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.ContainerId}`,
            {
                auth: {
                    username: 'Skyport',
                    password: instance.Node.apiKey
                }
            }
        );

        // Update user's instances
        let userInstances = await db.get(instance.User + '_instances') || [];
        userInstances = userInstances.filter(obj => obj.ContainerId !== instance.ContainerId);
        await db.set(instance.User + '_instances', userInstances);

        // Update global instances
        let globalInstances = await db.get('instances') || [];
        globalInstances = globalInstances.filter(obj => obj.ContainerId !== instance.ContainerId);
        await db.set('instances', globalInstances);

        // Delete instance-specific data
        await db.delete(instance.Id + '_instance');

    } catch (error) {
        console.error(`Error deleting instance ${instance.ContainerId}:`, error);
        // Even if the node is down, we should clean up our records
        throw error;
    }
}

async function updateDatabaseWithNewInstance(
    responseData,
    userId,
    node,
    image,
    memory,
    disk,
    cpu,
    ports,
    primary,
    name,
    Id,
    imagename
) {
    try {
        const rawImages = await db.get('images') || [];
        const imageData = rawImages.find(i => i.Name === imagename);

        const instanceData = {
            Name: name,
            Id,
            Node: {
                id: node.id,
                name: node.name,
                address: node.address,
                port: node.port,
                apiKey: node.apiKey // Note: Consider if you really want to store the API key here
            },
            User: userId,
            ContainerId: responseData.containerId,
            VolumeId: responseData.volumeId || Id,
            Memory: parseInt(memory),
            Disk: parseInt(disk) || 0,
            Cpu: parseInt(cpu),
            Ports: ports,
            Primary: primary,
            Image: image,
            AltImages: imageData ? imageData.AltImages : [],
            StopCommand: imageData ? imageData.StopCommand : undefined,
            imageData,
            Env: responseData.Env || [],
            State: responseData.state || 'running',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        // Update user's instances
        let userInstances = await db.get(`${userId}_instances`) || [];
        userInstances.push(instanceData);
        await db.set(`${userId}_instances`, userInstances);

        // Update global instances
        let globalInstances = await db.get('instances') || [];
        globalInstances.push(instanceData);
        await db.set('instances', globalInstances);

        // Store instance data
        await db.set(`${Id}_instance`, instanceData);

    } catch (error) {
        console.error('Error updating database with new instance:', error);
        throw error;
    }
}

async function prepareRequestData(image, memory, cpu, ports, name, node, Id, variables, imagename) {
    const rawImages = await db.get('images') || [];
    const imageData = rawImages.find(i => i.Name === imagename);

    const requestData = {
        method: 'post',
        url: `http://${node.address}:${node.port}/instances/create`,
        auth: {
            username: 'Skyport',
            password: node.apiKey,
        },
        headers: {
            'Content-Type': 'application/json',
        },
        data: {
            Name: name,
            Id,
            Image: image,
            Env: imageData ? imageData.Env : [],
            Scripts: imageData ? imageData.Scripts : [],
            Memory: parseInt(memory),
            Cpu: parseInt(cpu),
            ExposedPorts: {},
            PortBindings: {},
            variables: variables || {},
            AltImages: imageData ? imageData.AltImages : [],
            StopCommand: imageData ? imageData.StopCommand : '',
            imageData: imageData || {},
        },
        timeout: 30000 // 30 seconds timeout
    };

    if (ports) {
        const portMappings = typeof ports === 'string' ? ports.split(',') : Array.isArray(ports) ? ports : [];

        portMappings.forEach(portMapping => {
            if (typeof portMapping !== 'string') return;

            const [containerPort, hostPort] = portMapping.split(':').map(p => p.trim());
            if (!containerPort) return;

            // Handle TCP ports
            const tcpKey = `${containerPort}/tcp`;
            requestData.data.ExposedPorts[tcpKey] = {};
            requestData.data.PortBindings[tcpKey] = [{ HostPort: hostPort || containerPort }];

            // Handle UDP ports if specified
            if (containerPort.includes('/udp')) {
                const udpKey = containerPort;
                requestData.data.ExposedPorts[udpKey] = {};
                requestData.data.PortBindings[udpKey] = [{ HostPort: hostPort || containerPort.split('/')[0] }];
            }
        });
    }

    return requestData;
}

async function checkNodeStatus(node) {
    try {
        const response = await axios({
            method: 'get',
            url: `http://${node.address}:${node.port}/`,
            auth: {
                username: 'Skyport',
                password: node.apiKey
            },
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 5000 // 5 seconds timeout
        });

        const { versionFamily, versionRelease, online, remote, docker } = response.data;

        const updatedNode = {
            ...node,
            status: 'Online',
            versionFamily,
            versionRelease,
            remote,
            docker,
            lastSeen: new Date().toISOString()
        };

        await db.set(node.id + '_node', updatedNode);
        return updatedNode;

    } catch (error) {
        const updatedNode = {
            ...node,
            status: 'Offline',
            lastChecked: new Date().toISOString()
        };

        await db.set(node.id + '_node', updatedNode);
        return updatedNode;
    }
}

module.exports = router;