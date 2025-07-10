const express = require("express");
const axios = require("axios");
const { db } = require("../../handlers/db.js");
const { logAudit } = require("../../handlers/auditlog");

const router = express.Router();

// Constants
const NODE_API_TIMEOUT = 15000; // 15 seconds
const MAX_MEMORY = 1024 * 1024; // 1TB (in MB)
const MAX_CPU = 1024; // Arbitrary high limit

/**
 * Middleware to verify if the user is an administrator.
 * @param {Object} req - The request object
 * @param {Object} res - The response object
 * @param {Function} next - The next middleware function
 * @returns {void}
 */
function isAdmin(req, res, next) {
    if (!req.user || req.user.admin !== true) {
        return res
            .status(403)
            .json({ message: "Forbidden: Admin access required" });
    }
    next();
}

/**
 * PUT /instances/edit/:id
 * Handles the editing of an existing instance with comprehensive validation
 */
router.put("/instances/edit/:id", isAdmin, async (req, res) => {
    try {
        // Validate authentication
        if (!req.user) {
            return res.status(401).json({ message: "Authentication required" });
        }

        // Validate instance ID
        const { id } = req.params;
        if (!id || typeof id !== "string" || id.length > 64) {
            return res.status(400).json({ message: "Invalid instance ID" });
        }

        // Validate request body
        const { Image, Memory, Cpu } = req.body;
        if (!Image && !Memory && !Cpu) {
            return res.status(400).json({
                message: "At least one update parameter (Image, Memory, Cpu) is required",
            });
        }

        // Validate memory if provided
        if (Memory !== undefined) {
            if (isNaN(Memory)){
                return res.status(400).json({ message: "Memory must be a number" });
            }
            const memoryNum = parseFloat(Memory);
            if (memoryNum <= 0 || memoryNum > MAX_MEMORY) {
                return res.status(400).json({ 
                    message: `Memory must be between 0 and ${MAX_MEMORY} MB`
                });
            }
        }

        // Validate CPU if provided
        if (Cpu !== undefined) {
            if (isNaN(Cpu)) {
                return res.status(400).json({ message: "CPU must be a number" });
            }
            const cpuNum = parseFloat(Cpu);
            if (cpuNum <= 0 || cpuNum > MAX_CPU) {
                return res.status(400).json({ 
                    message: `CPU must be between 0 and ${MAX_CPU}`
                });
            }
        }

        // Validate image if provided
        if (Image && (typeof Image !== "string" || Image.length > 512)) {
            return res.status(400).json({ 
                message: "Invalid image format or length" 
            });
        }

        // Get instance from database
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.status(404).json({ message: "Instance not found" });
        }

        // Validate node information
        if (!instance.Node || 
            !instance.Node.address || 
            !instance.Node.port || 
            !instance.Node.apiKey) {
            return res.status(500).json({
                message: "Invalid node configuration for this instance",
            });
        }

        // Prepare and send request to node with retry logic
        const requestData = prepareEditRequestData(
            instance,
            Image,
            Memory,
            Cpu,
        );
        
        const response = await axios(requestData)
            .catch(async (error) => {
                console.error("Node API request failed:", error);
                // Retry once if it's a network error or 5xx response
                if (error.code === 'ECONNABORTED' || 
                    (error.response && error.response.status >= 500)) {
                    console.log("Retrying node API request...");
                    return axios(requestData);
                }
                throw error;
            });

        if (!response.data || !response.data.newContainerId) {
            throw new Error("Invalid response from node API");
        }

        // Update database records with transaction
        const updatedInstance = await updateInstanceInDatabase(
            id,
            instance,
            Image,
            Memory,
            Cpu,
            response.data.newContainerId,
        );

        // Log the audit event
        await logAudit(
            req.user.userId,
            req.user.username,
            "instance:edit",
            req.ip,
            {
                oldContainerId: id,
                newContainerId: response.data.newContainerId,
                changes: { 
                    Image: Image ? "updated" : "unchanged",
                    Memory: Memory ? "updated" : "unchanged",
                    Cpu: Cpu ? "updated" : "unchanged",
                },
            },
        );

        res.status(200).json({
            message: "Instance updated successfully",
            oldContainerId: id,
            newContainerId: response.data.newContainerId,
            changes: {
                Image: Image ? "updated" : "unchanged",
                Memory: Memory ? "updated" : "unchanged",
                Cpu: Cpu ? "updated" : "unchanged",
            },
        });
    } catch (error) {
        console.error("Error updating instance:", error);

        const statusCode = error.response?.status || 500;
        const errorMessage = error.response?.data?.message || 
                            error.message || 
                            "Failed to update instance";

        res.status(statusCode).json({
            message: errorMessage,
            details: process.env.NODE_ENV === "development" ? 
                {
                    stack: error.stack,
                    fullError: JSON.stringify(error, Object.getOwnPropertyNames(error))
                } : undefined,
        });
    }
});

/**
 * Prepares the request data for editing an instance
 * @param {Object} instance - The instance object
 * @param {string} [Image] - New image
 * @param {number} [Memory] - New memory
 * @param {number} [Cpu] - New CPU
 * @returns {Object} Axios request configuration
 */
function prepareEditRequestData(instance, Image, Memory, Cpu) {
    const nodeUrl = `http://${instance.Node.address}:${instance.Node.port}`;
    
    return {
        method: "put",
        url: `${nodeUrl}/instances/edit/${instance.ContainerId}`,
        auth: {
            username: "Skyport",
            password: instance.Node.apiKey,
        },
        headers: {
            "Content-Type": "application/json",
            "X-Requested-By": "CODERXSA-API",
        },
        data: {
            Image: Image !== undefined ? Image : instance.Image,
            Memory: Memory !== undefined ? Memory : instance.Memory,
            Cpu: Cpu !== undefined ? Cpu : instance.Cpu,
            VolumeId: instance.VolumeId,
        },
        timeout: NODE_API_TIMEOUT,
        validateStatus: (status) => status < 500, // Don't throw for 4xx errors
    };
}

/**
 * Updates all database records related to an instance
 * @param {string} id - Old container ID
 * @param {Object} instance - Original instance data
 * @param {string} [Image] - New image
 * @param {number} [Memory] - New memory
 * @param {number} [Cpu] - New CPU
 * @param {string} newContainerId - New container ID
 * @returns {Promise<Object>} The updated instance
 */
async function updateInstanceInDatabase(
    id,
    instance,
    Image,
    Memory,
    Cpu,
    newContainerId,
) {
    const updatedInstance = {
        ...instance,
        Image: Image !== undefined ? Image : instance.Image,
        Memory: Memory !== undefined ? Memory : instance.Memory,
        Cpu: Cpu !== undefined ? Cpu : instance.Cpu,
        ContainerId: newContainerId,
        updatedAt: new Date().toISOString(),
    };

    // Use transaction for atomic updates
    const batch = db.batch()
        .set(`${newContainerId}_instance`, updatedInstance)
        .del(`${id}_instance`);

    // Update user instances reference
    const userInstances = (await db.get(`${instance.User}_instances`)) || [];
    const userInstanceIndex = userInstances.findIndex(
        (inst) => inst.ContainerId === id,
    );
    
    if (userInstanceIndex !== -1) {
        const updatedUserInstances = [...userInstances];
        updatedUserInstances[userInstanceIndex] = {
            ...updatedUserInstances[userInstanceIndex],
            ...updatedInstance,
        };
        batch.set(`${instance.User}_instances`, updatedUserInstances);
    }

    // Update global instances reference
    const globalInstances = (await db.get("instances")) || [];
    const globalInstanceIndex = globalInstances.findIndex(
        (inst) => inst.ContainerId === id,
    );
    
    if (globalInstanceIndex !== -1) {
        const updatedGlobalInstances = [...globalInstances];
        updatedGlobalInstances[globalInstanceIndex] = {
            ...updatedGlobalInstances[globalInstanceIndex],
            ...updatedInstance,
        };
        batch.set("instances", updatedGlobalInstances);
    }

    // Execute all updates in a single transaction
    await batch.write();

    return updatedInstance;
}

module.exports = router;