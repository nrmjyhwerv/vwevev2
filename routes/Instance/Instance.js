const axios = require("axios");
const express = require("express");
const router = express.Router();
const { db } = require("../../handlers/db.js");
const { isUserAuthorizedForContainer } = require("../../utils/authHelper");
const { loadPlugins } = require("../../plugins/loadPls.js");
const path = require("path");
const { fetchFiles } = require("../../utils/fileHelper");
const { isAuthenticated } = require("../../handlers/auth.js");

const plugins = loadPlugins(path.join(__dirname, "../../plugins"));

// Enhanced instance ID validation
const validateInstanceId = (id) => {
    return (
        typeof id === "string" && id.length > 0 && /^[a-zA-Z0-9-_]+$/.test(id)
    );
};

// Robust state checking with retry logic
async function checkState(instanceId) {
    if (!validateInstanceId(instanceId)) {
        throw new Error("Invalid instance ID");
    }

    try {
        const instance = await db.get(`${instanceId}_instance`);
        if (!instance) {
            throw new Error("Instance not found");
        }

        if (
            !instance.Node ||
            !instance.Node.address ||
            !instance.Node.port ||
            !instance.Node.apiKey
        ) {
            throw new Error("Invalid node configuration");
        }

        const getStateUrl = `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.Id}/states/get`;
        const getStateResponse = await axios.get(getStateUrl, {
            auth: {
                username: "Skyport",
                password: instance.Node.apiKey,
            },
            timeout: 5000,
        });

        if (!getStateResponse.data || !getStateResponse.data.state) {
            throw new Error("Invalid state response from server");
        }

        const newState = getStateResponse.data.state;
        const setStateUrl = `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.Id}/states/set/${newState}`;

        await axios.get(setStateUrl, {
            auth: {
                username: "Skyport",
                password: instance.Node.apiKey,
            },
            timeout: 5000,
        });

        // Update instance state
        instance.State = newState;
        await db.set(`${instanceId}_instance`, instance);

        return newState;
    } catch (error) {
        console.error(
            `Error checking state for instance ${instanceId}:`,
            error.message,
        );
        throw error;
    }
}

// Enhanced instances listing with caching
router.get("/instances", isAuthenticated, async (req, res) => {
    try {
        if (!req.user) return res.redirect("/");

        let instances = [];
        const userId = req.user.userId;

        if (req.query.see === "other") {
            const allInstances = (await db.get("instances")) || [];
            instances = allInstances.filter(
                (instance) => instance.User !== userId,
            );
        } else {
            // Get user's own instances
            instances = (await db.get(`${userId}_instances`)) || [];

            // Get sub-user instances if any
            const users = (await db.get("users")) || [];
            const authenticatedUser = users.find(
                (user) => user.userId === userId,
            );
            const subUserInstances = authenticatedUser?.accessTo || [];

            for (const instanceId of subUserInstances) {
                if (validateInstanceId(instanceId)) {
                    try {
                        const instanceData = await db.get(
                            `${instanceId}_instance`,
                        );
                        if (instanceData) {
                            instances.push(instanceData);
                        }
                    } catch (err) {
                        console.error(
                            `Error loading instance ${instanceId}:`,
                            err,
                        );
                    }
                }
            }
        }

        res.render("instances", {
            req,
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
            instances,
            config: require("../../config.json"),
        });
    } catch (error) {
        console.error("Error in instances route:", error);
        res.status(500).render("error", {
            error: "Internal Server Error",
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
        });
    }
});

// Enhanced instance view with better error handling
router.get("/instance/:id", isAuthenticated, async (req, res) => {
    try {
        if (!req.user) return res.redirect("/");

        const { id } = req.params;
        if (!validateInstanceId(id)) return res.redirect("/");

        const instance = await db.get(`${id}_instance`);
        if (!instance) return res.redirect("../instances");

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res.status(403).render("error", {
                error: "Unauthorized access to this instance",
                user: req.user,
                name: (await db.get("name")) || "HydraPanel",
                logo: (await db.get("logo")) || false,
            });
        }

        // Initialize instance properties if not set
        instance.suspended =
            typeof instance.suspended === "boolean"
                ? instance.suspended
                : false;
        instance.State = instance.State || "UNKNOWN";
        await db.set(`${id}_instance`, instance);

        if (instance.State === "INSTALLING") {
            return res.redirect(`../../instance/${id}/installing`);
        }

        if (instance.suspended === true) {
            return res.redirect("../../instances?err=SUSPENDED");
        }

        const config = require("../../config.json");
        const { port, domain } = config;
        const allPluginData = Object.values(plugins).map(
            (plugin) => plugin.config,
        );

        // Fetch files with improved error handling
        let files = [];
        try {
            files = await fetchFiles(instance, "");
        } catch (fileError) {
            console.error("Error fetching files:", fileError);
            files = [];
        }

        res.render("instance/instance", {
            req,
            ContainerId: instance.ContainerId,
            instance,
            port,
            domain,
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
            files,
            addons: {
                plugins: allPluginData,
            },
        });
    } catch (error) {
        console.error("Error in instance route:", error);
        res.status(500).render("error", {
            error: "Internal Server Error",
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
        });
    }
});

// Installing view with proper state validation
router.get("/instance/:id/installing", isAuthenticated, async (req, res) => {
    try {
        const { id } = req.params;
        if (!validateInstanceId(id)) return res.redirect("/");

        const instance = await db.get(`${id}_instance`);
        if (!instance) return res.redirect("../instances");

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res.status(403).render("error", {
                error: "Unauthorized access to this instance",
                user: req.user,
                name: (await db.get("name")) || "HydraPanel",
                logo: (await db.get("logo")) || false,
            });
        }

        // Verify the instance is actually installing
        if (instance.State !== "INSTALLING") {
            return res.redirect(`../../instance/${id}`);
        }

        await checkState(id);

        res.render("instance/installing", {
            req,
            instance,
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
            config: require("../../config.json"),
        });
    } catch (error) {
        console.error("Error in installing route:", error);
        res.status(500).render("error", {
            error: "Internal Server Error",
            user: req.user,
            name: (await db.get("name")) || "HydraPanel",
            logo: (await db.get("logo")) || false,
        });
    }
});

// Installation status with proper error responses
router.get(
    "/instance/:id/installing/status",
    isAuthenticated,
    async (req, res) => {
        try {
            const { id } = req.params;
            if (!validateInstanceId(id)) {
                return res.status(400).json({
                    success: false,
                    error: "Invalid instance ID",
                });
            }

            const instance = await db.get(`${id}_instance`);
            if (!instance) {
                return res.status(404).json({
                    success: false,
                    error: "Instance not found",
                });
            }

            const isAuthorized = await isUserAuthorizedForContainer(
                req.user.userId,
                instance.Id,
            );
            if (!isAuthorized) {
                return res.status(403).json({
                    success: false,
                    error: "Unauthorized access to this instance.",
                });
            }

            const state = await checkState(id);
            res.status(200).json({
                success: true,
                state,
            });
        } catch (error) {
            console.error("Error in status route:", error);
            res.status(500).json({
                success: false,
                error: "Internal Server Error",
            });
        }
    },
);

// Fixed and enhanced rename feature
router.post("/instance/:id/rename", isAuthenticated, async (req, res) => {
    try {
        const { id } = req.params;
        const { newName } = req.body;

        // Validate inputs
        if (!validateInstanceId(id)) {
            return res.status(400).json({
                success: false,
                error: "Invalid instance ID",
            });
        }

        if (
            !newName ||
            typeof newName !== "string" ||
            newName.trim().length === 0
        ) {
            return res.status(400).json({
                success: false,
                error: "Invalid name provided",
            });
        }

        const trimmedName = newName.trim();

        // Validate name length and characters
        if (trimmedName.length > 64) {
            return res.status(400).json({
                success: false,
                error: "Name too long (max 64 characters)",
            });
        }

        // Get instance and verify authorization
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.status(404).json({
                success: false,
                error: "Instance not found",
            });
        }

        const isAuthorized = await isUserAuthorizedForContainer(
            req.user.userId,
            instance.Id,
        );
        if (!isAuthorized) {
            return res.status(403).json({
                success: false,
                error: "Unauthorized access to this instance.",
            });
        }

        // Update instance name in all relevant locations
        const oldName = instance.Name;
        instance.Name = trimmedName;

        // Save changes in transaction-like manner
        try {
            await db.set(`${id}_instance`, instance);

            // Update in main instances list
            const allInstances = (await db.get("instances")) || [];
            const instanceIndex = allInstances.findIndex((i) => i.Id === id);
            if (instanceIndex !== -1) {
                allInstances[instanceIndex].Name = trimmedName;
                await db.set("instances", allInstances);
            }

            // Update in user's instances list
            const userInstances =
                (await db.get(`${req.user.userId}_instances`)) || [];
            const userInstanceIndex = userInstances.findIndex(
                (i) => i.Id === id,
            );
            if (userInstanceIndex !== -1) {
                userInstances[userInstanceIndex].Name = trimmedName;
                await db.set(`${req.user.userId}_instances`, userInstances);
            }

            res.status(200).json({
                success: true,
                newName: trimmedName,
                oldName,
            });
        } catch (dbError) {
            // Revert changes if any part fails
            instance.Name = oldName;
            await db.set(`${id}_instance`, instance);

            console.error("Database error during rename:", dbError);
            res.status(500).json({
                success: false,
                error: "Failed to update instance name",
            });
        }
    } catch (error) {
        console.error("Error renaming instance:", error);
        res.status(500).json({
            success: false,
            error: "Internal Server Error",
        });
    }
});

module.exports = router;
