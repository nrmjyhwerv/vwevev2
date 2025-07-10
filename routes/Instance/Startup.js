const express = require("express");
const axios = require("axios");
const { db } = require("../../handlers/db.js");
const { logAudit } = require("../../handlers/auditlog");
const { v4: uuid } = require("uuid");
const { loadPlugins } = require("../../plugins/loadPls.js");
const { isUserAuthorizedForContainer } = require("../../utils/authHelper");
const path = require("path");

const plugins = loadPlugins(path.join(__dirname, "../../plugins"));
const router = express.Router();

const allPluginData = Object.values(plugins).map((plugin) => plugin.config);

/**
 * GET /instance/:id/startup
 * Renders the instance startup page with the available alternative images.
 */
router.get("/instance/:id/startup", async (req, res) => {
    if (!req.user) return res.redirect("/");

    const { id } = req.params;

    if (!id) {
        return res.redirect("/instances");
    }

    try {
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.redirect("../../instances");
        }

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res
                .status(403)
                .send("Unauthorized access to this instance.");
        }

        if (typeof instance.suspended === "undefined") {
            instance.suspended = false;
            await db.set(`${id}_instance`, instance);
        }

        if (instance.suspended === true) {
            return res.redirect("../../instances?err=SUSPENDED");
        }

        res.render("instance/startup.ejs", {
            req,
            user: req.user,
            name: (await db.get("name")) || "DracoPanel",
            logo: (await db.get("logo")) || false,
            instance,
            addons: {
                plugins: allPluginData,
            },
        });
    } catch (error) {
        console.error("Error fetching instance data:", error);
        res.status(500).json({
            error: "Failed to load instance data",
            details: error.message,
        });
    }
});

/**
 * POST /instances/startup/changevariable/:id
 * Handles the change of a specific environment variable for the instance.
 */
router.post("/instances/startup/changevariable/:id", async (req, res) => {
    if (!req.user) return res.redirect("/");

    const { id } = req.params;
    const { variable, value } = req.query;

    if (!id || !variable) {
        return res.status(400).json({ error: "Missing parameters" });
    }

    try {
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.status(404).json({ error: "Instance not found" });
        }

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res
                .status(403)
                .send("Unauthorized access to this instance.");
        }

        if (typeof instance.suspended === "undefined") {
            instance.suspended = false;
            await db.set(`${id}_instance`, instance);
        }

        if (instance.suspended === true) {
            return res.status(403).json({ error: "Instance is suspended" });
        }

        // Handle environment variables more robustly
        let envUpdated = false;
        const updatedEnv = instance.Env.map((envVar) => {
            const [key] = envVar.split("=");
            if (key === variable) {
                envUpdated = true;
                return `${key}=${value || ""}`;
            }
            return envVar;
        });

        // Add new variable if it didn't exist
        if (!envUpdated) {
            updatedEnv.push(`${variable}=${value || ""}`);
        }

        const updatedInstance = { ...instance, Env: updatedEnv };
        await db.set(`${id}_instance`, updatedInstance);

        // Update in all instances arrays
        await updateInstanceInUserAndGlobalArrays(updatedInstance);

        logAudit(
            req.user.userId,
            req.user.username,
            "instance:variableChange",
            req.ip,
            { variable, value },
        );
        res.json({ success: true });
    } catch (error) {
        console.error("Error updating environment variable:", error);
        res.status(500).json({
            error: "Failed to update environment variable",
            details: error.message,
        });
    }
});

/**
 * POST /instances/startup/rename/:id
 * Improved rename feature with validation and proper error handling
 */
router.get("/instance/:id/change/name/:name", async (req, res) => {
    if (!req.user) {
        return res.status(401).send("Authentication required");
    }

    const { id, name } = req.params;

    if (!name || name.trim() === "") {
        return res.status(400).send("Name cannot be empty");
    }

    if (name.length > 50) {
        return res.status(400).send("Name cannot exceed 50 characters");
    }

    if (!/^[a-zA-Z0-9 ]+$/.test(name)) {
        return res
            .status(400)
            .send("Name can only contain alphanumeric characters and spaces");
    }

    let instance = await db.get(id + "_instance");
    if (!instance) {
        return res.status(404).send("Instance not found");
    }

    const isAuthorized = await isUserAuthorizedForContainer(
        req.user.userId,
        instance.Id,
    );
    if (!isAuthorized) {
        return res.status(403).send("Unauthorized access to this instance.");
    }

    const suspended = await isInstanceSuspended(req.user.userId, instance, id);
    if (suspended === true) {
        return res.render("instance/suspended", { req, user: req.user });
    }

    const trimmedName = name.trim();
    instance.Name = trimmedName;

    // Update instance in userInstances
    let userInstances = (await db.get(req.user.userId + "_instances")) || [];
    const userInstanceIndex = userInstances.findIndex(
        (inst) => inst.ContainerId === id,
    );
    if (userInstanceIndex !== -1) {
        userInstances[userInstanceIndex].Name = trimmedName;
        await db.set(req.user.userId + "_instances", userInstances);
    }

    // Update instance in globalInstances
    let globalInstances = (await db.get("instances")) || [];
    const globalInstanceIndex = globalInstances.findIndex(
        (inst) => inst.ContainerId === id,
    );
    if (globalInstanceIndex !== -1) {
        globalInstances[globalInstanceIndex].Name = trimmedName;
        await db.set("instances", globalInstances);
    }

    // Save the updated instance
    await db.set(id + "_instance", instance);

    res.redirect("/instance/" + id + "/settings");
});

/**
 * GET /instances/startup/changeimage/:id
 * Handles the change of the instance image with improved error handling
 */
router.get("/instances/startup/changeimage/:id", async (req, res) => {
    if (!req.user) return res.redirect("/");

    const { id } = req.params;

    if (!id) {
        return res.redirect("/instances");
    }

    try {
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.redirect("/instances");
        }

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res
                .status(403)
                .send("Unauthorized access to this instance.");
        }

        if (typeof instance.suspended === "undefined") {
            instance.suspended = false;
            await db.set(`${id}_instance`, instance);
        }

        if (instance.suspended === true) {
            return res.redirect("../../instance/" + id + "/suspended");
        }

        const nodeId = instance.Node.id;
        const { image, user } = req.query;

        if (!image || !user || !nodeId) {
            return res.status(400).json({ error: "Missing parameters" });
        }

        const node = await db.get(`${nodeId}_node`);
        if (!node) {
            return res.status(400).json({ error: "Invalid node" });
        }

        const requestData = await prepareRequestData(
            image,
            instance.Memory,
            instance.Cpu,
            instance.Ports,
            instance.Name,
            node,
            id,
            instance.ContainerId,
            instance.Env,
        );
        const response = await axios(requestData);

        await updateDatabaseWithNewInstance(
            response.data,
            user,
            node,
            instance.imageData.Image,
            instance.Memory,
            instance.Cpu,
            instance.Ports,
            instance.Primary,
            instance.Name,
            id,
            image,
            instance.imageData,
            instance.Env,
        );

        logAudit(
            req.user.userId,
            req.user.username,
            "instance:imageChange",
            req.ip,
            { oldImage: instance.Image, newImage: image },
        );
        res.status(201).redirect(`/instance/${id}/startup`);
    } catch (error) {
        console.error("Error changing instance image:", error);
        const errorDetails = error.response
            ? error.response.data || "No additional error info"
            : error.message;

        res.status(500).json({
            error: "Failed to change container image",
            details: errorDetails,
        });
    }
});

async function prepareRequestData(
    image,
    memory,
    cpu,
    ports,
    name,
    node,
    id,
    containerId,
    Env,
) {
    const rawImages = (await db.get("images")) || [];
    const imageData = rawImages.find((i) => i.Image === image);

    const requestData = {
        method: "post",
        url: `http://${node.address}:${node.port}/instances/redeploy/${containerId}`,
        auth: {
            username: "Skyport",
            password: node.apiKey,
        },
        headers: {
            "Content-Type": "application/json",
        },
        data: {
            Name: name,
            Id: id,
            Image: image,
            Env: Array.isArray(Env) ? Env : [],
            Scripts: imageData ? imageData.Scripts : undefined,
            Memory: memory ? parseInt(memory) : undefined,
            Cpu: cpu ? parseInt(cpu) : undefined,
            ExposedPorts: {},
            PortBindings: {},
            AltImages: imageData ? imageData.AltImages : [],
        },
    };

    if (ports) {
        ports.split(",").forEach((portMapping) => {
            const [containerPort, hostPort] = portMapping.split(":");
            if (containerPort && hostPort) {
                const key = `${containerPort}/tcp`;
                requestData.data.ExposedPorts[key] = {};
                requestData.data.PortBindings[key] = [{ HostPort: hostPort }];
            }
        });
    }
    return requestData;
}

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
    currentimage,
    imagedata,
    Env,
) {
    const rawImages = (await db.get("images")) || [];
    const imageData = rawImages.find((i) => i.Image === image);
    const altImages = imageData ? imageData.AltImages : [];

    const instanceData = {
        Name: name,
        Id: id,
        Node: node,
        User: userId,
        ContainerId: responseData.containerId,
        VolumeId: id,
        Memory: parseInt(memory) || 0,
        Cpu: parseInt(cpu) || 0,
        Ports: ports,
        Primary: primary,
        currentimage: currentimage,
        Env: Array.isArray(Env) ? Env : [],
        Image: image,
        AltImages: altImages,
        imageData: imagedata,
        suspended: false,
    };

    await updateInstanceInUserAndGlobalArrays(instanceData);
    await db.set(`${id}_instance`, instanceData);
}

async function updateInstanceInUserAndGlobalArrays(instanceData) {
    // Update user instances
    let userInstances = (await db.get(`${instanceData.User}_instances`)) || [];
    userInstances = userInstances.filter(
        (instance) => instance.Id !== instanceData.Id,
    );
    userInstances.push(instanceData);
    await db.set(`${instanceData.User}_instances`, userInstances);

    // Update global instances
    let globalInstances = (await db.get("instances")) || [];
    globalInstances = globalInstances.filter(
        (instance) => instance.Id !== instanceData.Id,
    );
    globalInstances.push(instanceData);
    await db.set("instances", globalInstances);
}

module.exports = router;
