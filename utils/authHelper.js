const { db } = require("../handlers/db.js");
const CatLoggr = require("cat-loggr");
const log = new CatLoggr();

/**
 * Checks if the user is authorized to access the specified container ID.
 * @param {string} userId - The unique identifier of the user.
 * @param {string} containerId - The container ID to check authorization for.
 * @returns {Promise<boolean>} True if the user is authorized, otherwise false.
 */
async function isUserAuthorizedForContainer(userId, containerId) {
    if (!userId || !containerId) {
        log.error("Missing required parameters:", { userId, containerId });
        return false;
    }

    try {
        const [userInstances, users] = await Promise.all([
            db.get(`${userId}_instances`) || [],
            db.get("users") || [],
        ]);

        const user = users.find((user) => user.userId === userId);
        if (!user) {
            log.error("User not found:", userId);
            return false;
        }

        // Admins have access to everything
        if (user.admin) {
            return true;
        }

        const subUserInstances = user.accessTo || [];
        const isInSubUserInstances = subUserInstances.includes(containerId);
        const isInUserInstances = userInstances.some(
            (instance) => instance.Id === containerId,
        );

        return isInSubUserInstances || isInUserInstances;
    } catch (error) {
        log.error("Error checking user authorization:", error);
        return false;
    }
}

/**
 * Checks if an instance is suspended and handles the suspension status.
 * @param {string} instanceId - The ID of the instance to check.
 * @returns {Promise<boolean>} True if the instance is suspended, false otherwise.
 */
async function isInstanceSuspended(instanceId) {
    if (!instanceId) {
        log.error("Instance ID is required");
        return false;
    }

    try {
        const instanceKey = `${instanceId}_instance`;
        let instance = await db.get(instanceKey);

        // Initialize if instance doesn't exist
        if (!instance) {
            instance = {
                suspended: false,
                createdAt: new Date().toISOString(),
                lastUpdated: new Date().toISOString(),
            };
            await db.set(instanceKey, instance);
            return false;
        }

        // Ensure required fields exist
        if (typeof instance.suspended === "undefined") {
            instance.suspended = false;
            instance.lastUpdated = new Date().toISOString();
            await db.set(instanceKey, instance);
        }

        return instance.suspended === true;
    } catch (error) {
        log.error("Error checking instance suspension status:", error);
        return false;
    }
}

module.exports = {
    isUserAuthorizedForContainer,
    isInstanceSuspended,
};
