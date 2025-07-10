const express = require("express");
const axios = require("axios");
const { db } = require("../../handlers/db.js");
const { logAudit } = require("../../handlers/auditlog.js");
const { isUserAuthorizedForContainer } = require("../../utils/authHelper");
const { v4: uuid } = require("uuid");

const router = express.Router();

// Constants
const DEFAULT_MEMORY = 512;
const DEFAULT_CPU = 100;
const REQUEST_TIMEOUT = 30000; // 30 seconds

/**
 * POST /instance/reinstall/:id
 * Handles the reinstallment of an existing instance
 */
router.post("/instance/reinstall/:id", async (req, res) => {
    if (!req.user) {
        return res.status(401).redirect("/");
    }

    const { id } = req.params;
    if (!id) {
        return res.status(400).redirect("/instances?err=MISSING_INSTANCE_ID");
    }

    try {
        // Get instance data with error handling
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.status(404).redirect("/instances?err=INSTANCE_NOT_FOUND");
        }

        // Verify user authorization
        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id
        );
        if (!isAuthorized) {
            return res.status(403).render("error", {
                message: "Unauthorized access to this instance.",
            });
        }

        // Check suspension status
        if (instance.suspended === true) {
            return res.redirect("../../instances?err=SUSPENDED");
        }

        // Validate required fields
        const requiredFields = [
            "Node", "Image", "Memory", "Cpu", "Name", 
            "User", "Primary", "ContainerId"
        ];
        const missingFields = requiredFields.filter(field => !instance[field]);
        
        if (missingFields.length > 0) {
            return res.status(400).json({
                error: "Missing required parameters",
                missingFields
            });
        }

        // Destructure with defaults
        const {
            Node: node,
            Image: image,
            Memory: memory = DEFAULT_MEMORY,
            Cpu: cpu = DEFAULT_CPU,
            Ports: ports = "",
            Name: name,
            User: user,
            Primary: primary,
            ContainerId: containerId,
            Env = {},
        } = instance;

        // Prepare and send reinstall request
        const requestData = await prepareRequestData(
            image,
            memory,
            cpu,
            ports,
            name,
            node,
            id,
            containerId,
            Env
        );
        
        const response = await axios(requestData);

        if (!response?.data?.containerId) {
            throw new Error("Invalid response from node: Missing containerId");
        }

        // Update database with new instance
        await updateDatabaseWithNewInstance(
            response.data,
            user,
            node,
            image,
            memory,
            cpu,
            ports,
            primary,
            name,
            id,
            Env
        );

        // Log the action
        await logAudit(
            req.user.userId,
            `Reinstalled instance ${name} (${id})`,
            "instance",
            id
        );

        return res.status(201).redirect(`../../instance/${id}`);
    } catch (error) {
        console.error("Error reinstalling instance:", error);
        return handleReinstallError(res, error);
    }
});

/**
 * Handles different types of errors and sends appropriate responses
 */
function handleReinstallError(res, error) {
    let statusCode = 500;
    let errorMessage = "Failed to reinstall container";
    let errorDetails = {};

    if (error.response) {
        statusCode = error.response.status || 502; // Bad Gateway if node fails
        errorMessage += `: Node responded with ${statusCode}`;
        errorDetails = {
            nodeResponse: error.response.data,
            status: error.response.status,
            headers: error.response.headers
        };
    } else if (error.request) {
        statusCode = 504; // Gateway Timeout
        errorMessage += ": No response received from node";
        errorDetails = {
            request: error.request,
            message: "Node may be offline or unreachable"
        };
    } else if (error.code === "ECONNABORTED") {
        statusCode = 504;
        errorMessage += ": Request to node timed out";
    } else {
        errorDetails = {
            message: error.message,
            stack: error.stack
        };
    }

    // For API requests, return JSON. For browser requests, redirect with error
    if (res.get("Accept")?.includes("application/json")) {
        return res.status(statusCode).json({
            error: errorMessage,
            details: errorDetails
        });
    } else {
        return res.redirect(`../../instances?err=REINSTALL_FAILED&message=${encodeURIComponent(errorMessage)}`);
    }
}

/**
 * Prepares the request data for reinstalling an instance
 */
async function prepareRequestData(
    image,
    memory,
    cpu,
    ports,
    name,
    node,
    id,
    containerId,
    Env
) {
    try {
        const rawImages = (await db.get("images")) || [];
        const imageData = rawImages.find((i) => i.Image === image);

        if (!imageData) {
            throw new Error(`Image ${image} not found in database`);
        }

        if (!node?.address || !node?.port || !node?.apiKey) {
            throw new Error("Invalid node configuration");
        }

        const requestData = {
            method: "post",
            url: `http://${node.address}:${node.port}/instances/reinstall/${containerId}`,
            auth: {
                username: "Skyport",
                password: node.apiKey,
            },
            headers: {
                "Content-Type": "application/json",
                "X-Request-ID": uuid(),
                "X-Instance-ID": id,
            },
            timeout: REQUEST_TIMEOUT,
            data: {
                Name: name,
                Id: id,
                Image: image,
                Env: Env || {},
                Scripts: imageData?.Scripts || [],
                Memory: parseInt(memory) || DEFAULT_MEMORY,
                Cpu: parseInt(cpu) || DEFAULT_CPU,
                ExposedPorts: {},
                PortBindings: {},
                AltImages: imageData?.AltImages || [],
                imageData: imageData || {},
            },
        };

        // Process port mappings if they exist
        if (ports && typeof ports === "string") {
            const portMappings = ports.split(",")
                .map(p => p.trim())
                .filter(p => p);

            portMappings.forEach((portMapping) => {
                const [containerPort, hostPort] = portMapping.split(":");
                
                if (containerPort && hostPort) {
                    const key = `${containerPort}/tcp`;
                    requestData.data.ExposedPorts[key] = {};
                    requestData.data.PortBindings[key] = [
                        { HostPort: hostPort },
                    ];
                }
            });
        }

        return requestData;
    } catch (error) {
        console.error("Error preparing request data:", error);
        throw new Error(`Failed to prepare request data: ${error.message}`);
    }
}

/**
 * Updates all relevant database records with the new instance information
 */
async function updateDatabaseWithNewInstance(
    responseData,
    userId,
    node,
    image,
    memory,
    cpu,
    ports,
    primary,
    name,
    id,
    Env
) {
    const dbUpdateStart = Date.now();
    
    try {
        const rawImages = (await db.get("images")) || [];
        const imageData = rawImages.find((i) => i.Image === image);

        const now = new Date().toISOString();
        const instanceData = {
            Name: name,
            Id: id,
            Node: node,
            User: userId,
            ContainerId: responseData.containerId,
            VolumeId: id,
            Memory: parseInt(memory) || DEFAULT_MEMORY,
            Cpu: parseInt(cpu) || DEFAULT_CPU,
            Ports: ports,
            Primary: primary,
            Image: image,
            AltImages: imageData?.AltImages || [],
            imageData: imageData || {},
            Env: Env || {},
            createdAt: now,
            updatedAt: now,
            status: "reinstalling",
            lastOperation: {
                type: "reinstall",
                timestamp: now,
                status: "completed"
            }
        };

        // Start a transaction-like operation (since many key-value stores don't support real transactions)
        const batchUpdates = [];

        // Update user instances
        let userInstances = (await db.get(`${userId}_instances`)) || [];
        userInstances = userInstances.filter((instance) => instance.Id !== id);
        userInstances.push(instanceData);
        batchUpdates.push(db.set(`${userId}_instances`, userInstances));

        // Update global instances
        let globalInstances = (await db.get("instances")) || [];
        globalInstances = globalInstances.filter((instance) => instance.Id !== id);
        globalInstances.push(instanceData);
        batchUpdates.push(db.set("instances", globalInstances));

        // Update individual instance record
        batchUpdates.push(db.set(`${id}_instance`, instanceData));

        // Execute all updates in parallel
        await Promise.all(batchUpdates);

        // Add audit log
        await logAudit(
            userId,
            `Updated instance ${name} (${id}) in database`,
            "database",
            id
        );

        console.log(`Database updates completed in ${Date.now() - dbUpdateStart}ms`);
    } catch (error) {
        console.error("Error updating database:", error);
        
        // Try to restore previous state if possible
        try {
            await logAudit(
                userId,
                `Failed to update database for instance ${name} (${id}): ${error.message}`,
                "database_error",
                id
            );
        } catch (auditError) {
            console.error("Failed to log audit trail:", auditError);
        }

        throw new Error(`Failed to update database: ${error.message}`);
    }
}

module.exports = router;