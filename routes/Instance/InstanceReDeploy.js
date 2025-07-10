const express = require('express');
const axios = require('axios');
const { db } = require('../../handlers/db.js');
const { logAudit } = require('../../handlers/auditlog');
const { v4: uuid } = require('uuid');

const router = express.Router();

/**
 * Middleware to verify admin privileges with proper error handling
 */
function isAdmin(req, res, next) {
    try {
        if (!req.user || req.user.admin !== true) {
            logAudit(req.user?.userId || 'unknown', req.user?.username || 'unknown', 'unauthorized_access:admin_route', req.ip);
            return res.status(403).redirect('../');
        }
        next();
    } catch (error) {
        console.error('Admin check middleware error:', error);
        res.status(500).json({ error: 'Internal server error during authentication' });
    }
}

/**
 * Validates instance redeployment parameters
 */
function validateRedeploymentParams(req, res, next) {
    const { id } = req.params;
    const { image, memory, cpu, ports, name, user, primary } = req.query;

    if (!id) {
        return res.status(400).redirect('/admin/instances?error=missing_instance_id');
    }

    const missingParams = [];
    if (!image) missingParams.push('image');
    if (!memory) missingParams.push('memory');
    if (!cpu) missingParams.push('cpu');
    if (!ports) missingParams.push('ports');
    if (!name) missingParams.push('name');
    if (!user) missingParams.push('user');
    if (!primary) missingParams.push('primary');

    if (missingParams.length > 0) {
        return res.status(400).json({ 
            error: 'Missing required parameters',
            missing: missingParams
        });
    }

    // Validate port format
    const portRegex = /^(\d+:\d+)(,\d+:\d+)*$/;
    if (!portRegex.test(ports)) {
        return res.status(400).json({ 
            error: 'Invalid port format',
            details: 'Ports must be in format "hostPort:containerPort" separated by commas'
        });
    }

    // Validate numeric values
    if (isNaN(parseInt(memory))) {
        return res.status(400).json({ 
            error: 'Invalid memory value',
            details: 'Memory must be a number'
        });
    }

    if (isNaN(parseInt(cpu))) {
        return res.status(400).json({ 
            error: 'Invalid CPU value',
            details: 'CPU must be a number'
        });
    }

    next();
}

/**
 * GET /instances/redeploy/:id
 * Redeploys an existing instance with improved error handling and validation
 */
router.get('/instances/redeploy/:id', isAdmin, validateRedeploymentParams, async (req, res) => {
    const { id } = req.params;
    const { image, memory, cpu, ports, name, user, primary } = req.query;

    try {
        // Get instance data with proper error handling
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            logAudit(req.user.userId, req.user.username, 'instance:redeploy_fail:not_found', req.ip, { instanceId: id });
            return res.status(404).redirect('/admin/instances?error=instance_not_found');
        }

        const nodeId = instance.Node.id;
        if (!nodeId) {
            return res.status(400).json({ error: 'Instance has no associated node' });
        }

        // Extract short image name safely
        const imageMatch = image.match(/\(([^)]+)\)/);
        if (!imageMatch || !imageMatch[1]) {
            return res.status(400).json({ 
                error: 'Invalid image format',
                details: 'Image must contain the actual image name in parentheses'
            });
        }
        const shortimage = imageMatch[1];

        // Get node data with validation
        const node = await db.get(`${nodeId}_node`);
        if (!node) {
            logAudit(req.user.userId, req.user.username, 'instance:redeploy_fail:invalid_node', req.ip, { nodeId });
            return res.status(400).json({ 
                error: 'Invalid node',
                details: 'The node associated with this instance no longer exists'
            });
        }

        // Verify the container exists before redeploying
        try {
            const containerCheck = await axios({
                method: 'get',
                url: `http://${node.address}:${node.port}/instances/${instance.ContainerId}`,
                auth: {
                    username: 'Skyport',
                    password: node.apiKey
                }
            });

            if (!containerCheck.data) {
                throw new Error('Container not found');
            }
        } catch (checkError) {
            console.error('Container check failed:', checkError);
            logAudit(req.user.userId, req.user.username, 'instance:redeploy_fail:container_check', req.ip, { 
                instanceId: id,
                error: checkError.message 
            });
            return res.status(400).json({ 
                error: 'Container check failed',
                details: 'The existing container could not be verified'
            });
        }

        // Prepare and send redeployment request
        const requestData = await prepareRequestData(
            shortimage, memory, cpu, ports, name, node, id, 
            instance.ContainerId, instance.Env
        );

        const response = await axios(requestData).catch(async (error) => {
            console.error('Redeployment API error:', error);
            const errorDetails = error.response ? {
                status: error.response.status,
                data: error.response.data
            } : { message: error.message };
            
            logAudit(req.user.userId, req.user.username, 'instance:redeploy_fail:api_error', req.ip, {
                instanceId: id,
                error: errorDetails
            });
            
            throw error;
        });

        // Update database with new instance data
        await updateDatabaseWithNewInstance(
            response.data, user, node, shortimage, memory, cpu, 
            ports, primary, name, id, instance.Env, instance.imageData
        ).catch(async (dbError) => {
            console.error('Database update error:', dbError);
            logAudit(req.user.userId, req.user.username, 'instance:redeploy_fail:db_update', req.ip, {
                instanceId: id,
                error: dbError.message
            });
            
            // Attempt to rollback the redeployment
            try {
                await axios({
                    method: 'delete',
                    url: `http://${node.address}:${node.port}/instances/${response.data.containerId}`,
                    auth: {
                        username: 'Skyport',
                        password: node.apiKey
                    }
                });
            } catch (rollbackError) {
                console.error('Rollback failed:', rollbackError);
            }
            
            throw dbError;
        });

        // Log successful redeployment
        logAudit(req.user.userId, req.user.username, 'instance:redeploy', req.ip, {
            instanceId: id,
            newContainerId: response.data.containerId
        });

        // Send success response
        res.status(201).json({
            success: true,
            message: 'Container redeployed successfully',
            data: {
                containerId: response.data.containerId,
                volumeId: response.data.volumeId,
                instanceId: id
            }
        });

    } catch (error) {
        console.error('Redeployment process error:', error);
        const errorResponse = error.response ? {
            status: error.response.status,
            data: error.response.data
        } : { message: error.message };

        res.status(500).json({
            error: 'Instance redeployment failed',
            details: errorResponse,
            suggestion: 'Check logs for more details and try again'
        });
    }
});

/**
 * Prepares the request data for instance redeployment with enhanced validation
 */
async function prepareRequestData(image, memory, cpu, ports, name, node, id, containerId, Env) {
    try {
        const rawImages = await db.get('images') || [];
        const imageData = rawImages.find(i => i.Image === image);

        if (!imageData) {
            throw new Error(`Image ${image} not found in database`);
        }

        const requestData = {
            method: 'post',
            url: `http://${node.address}:${node.port}/instances/redeploy/${containerId}`,
            timeout: 30000, // 30 second timeout
            auth: {
                username: 'Skyport',
                password: node.apiKey
            },
            headers: {
                'Content-Type': 'application/json',
                'X-Request-ID': uuid()
            },
            data: {
                Name: name,
                Id: id,
                Image: image,
                Env: Array.isArray(Env) ? Env : [],
                Scripts: imageData.Scripts || [],
                Memory: parseInt(memory),
                Cpu: parseInt(cpu),
                ExposedPorts: {},
                PortBindings: {},
                AltImages: imageData.AltImages || [],
                Labels: {
                    'com.skyport.instance': 'true',
                    'com.skyport.instance.id': id,
                    'com.skyport.managed': 'true'
                }
            }
        };

        // Process port mappings with validation
        if (ports) {
            ports.split(',').forEach(portMapping => {
                const [hostPort, containerPort] = portMapping.split(':');
                
                if (!hostPort || !containerPort) {
                    throw new Error(`Invalid port mapping: ${portMapping}`);
                }

                if (isNaN(parseInt(hostPort))){
                    throw new Error(`Invalid host port: ${hostPort}`);
                }

                if (isNaN(parseInt(containerPort))) {
                    throw new Error(`Invalid container port: ${containerPort}`);
                }

                const key = `${containerPort}/tcp`;
                requestData.data.ExposedPorts[key] = {};
                requestData.data.PortBindings[key] = [{ HostPort: hostPort }];
            });
        }

        return requestData;
    } catch (error) {
        console.error('Error preparing request data:', error);
        throw error;
    }
}

/**
 * Updates database records for the redeployed instance with transaction-like safety
 */
async function updateDatabaseWithNewInstance(responseData, userId, node, image, memory, cpu, ports, primary, name, id, Env, imagedata) {
    try {
        const rawImages = await db.get('images') || [];
        const imageData = rawImages.find(i => i.Image === image) || { AltImages: [] };

        const instanceData = {
            Name: name,
            Id: id,
            Node: node,
            User: userId,
            ContainerId: responseData.containerId,
            VolumeId: id,
            Memory: parseInt(memory),
            Cpu: parseInt(cpu),
            Ports: ports,
            Primary: primary,
            Env: Array.isArray(Env) ? Env : [],
            Image: image,
            AltImages: imageData.AltImages || [],
            imageData: imagedata || {},
            LastUpdated: new Date().toISOString()
        };

        // Get current data
        const [userInstances, globalInstances] = await Promise.all([
            db.get(`${userId}_instances`) || [],
            db.get('instances') || []
        ]);

        // Filter out old instance
        const updatedUserInstances = userInstances.filter(instance => instance.Id !== id);
        const updatedGlobalInstances = globalInstances.filter(instance => instance.Id !== id);

        // Add updated instance
        updatedUserInstances.push(instanceData);
        updatedGlobalInstances.push(instanceData);

        // Update all records in sequence
        await db.set(`${userId}_instances`, updatedUserInstances);
        await db.set('instances', updatedGlobalInstances);
        await db.set(`${id}_instance`, instanceData);

        // Verify updates
        const verification = await Promise.all([
            db.get(`${userId}_instances`),
            db.get('instances'),
            db.get(`${id}_instance`)
        ]);

        if (!verification[0]?.some(i => i.Id === id) || 
            !verification[1]?.some(i => i.Id === id) || 
            !verification[2]) {
            throw new Error('Database verification failed after update');
        }

    } catch (error) {
        console.error('Database update error:', error);
        throw error;
    }
}

module.exports = router;