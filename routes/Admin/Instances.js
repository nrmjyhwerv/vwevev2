const express = require("express");
const router = express.Router();
const axios = require("axios");
const { db } = require("../../handlers/db.js");
const { logAudit } = require("../../handlers/auditlog.js");
const { isAdmin } = require("../../utils/isAdmin.js");
const fs = require("fs").promises;
const path = require("path");
const log = new (require("cat-loggr"))();

const WORKFLOWS_FILE_PATH = path.join(
  __dirname,
  "../../storage/workflows.json",
);
const DEFAULT_TIMEOUT = 5000;
const NODE_STATUS_CHECK_INTERVAL = 30000; // 30 seconds

// Cache for node status to avoid frequent checks
const nodeStatusCache = new Map();

/**
 * Helper function to validate instance structure
 */
function validateInstance(instance) {
  if (!instance || typeof instance !== "object") {
    throw new Error("Invalid instance: must be an object");
  }
  
  const requiredFields = ["Id", "ContainerId", "User", "Node"];
  for (const field of requiredFields) {
    if (!instance[field]) {
      throw new Error(`Invalid instance: missing required field ${field}`);
    }
  }

  if (!instance.Node.id || !instance.Node.address || !instance.Node.port || !instance.Node.apiKey) {
    throw new Error("Invalid instance: Node information incomplete");
  }
}

/**
 * Checks the status of a node with caching
 */
async function checkNodeStatus(node) {
  if (!node || !node.id) {
    throw new Error("Invalid node object provided");
  }

  // Check cache first
  const cachedNode = nodeStatusCache.get(node.id);
  if (cachedNode && Date.now() - new Date(cachedNode.lastChecked).getTime() < NODE_STATUS_CHECK_INTERVAL) {
    return cachedNode;
  }

  try {
    const requestConfig = {
      method: "get",
      url: `http://${node.address}:${node.port}/`,
      auth: {
        username: "Skyport",
        password: node.apiKey,
      },
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      timeout: DEFAULT_TIMEOUT,
      validateStatus: () => true // Accept all status codes
    };

    const response = await axios(requestConfig);

    if (response.status !== 200 || !response.data) {
      throw new Error(`Node returned status ${response.status}`);
    }

    if (!response.data.versionFamily || !response.data.versionRelease) {
      throw new Error("Invalid node response structure");
    }

    const { versionFamily, versionRelease, online, remote, docker } = response.data;

    const updatedNode = {
      ...node,
      status: online ? "Online" : "Offline",
      versionFamily,
      versionRelease,
      remote: remote || false,
      docker: docker || false,
      lastChecked: new Date().toISOString(),
      error: null
    };

    await db.set(`${node.id}_node`, updatedNode);
    nodeStatusCache.set(node.id, updatedNode);
    return updatedNode;
  } catch (error) {
    log.error(`Error checking status for node ${node.id}:`, error.message);

    const offlineNode = {
      ...node,
      status: "Offline",
      lastChecked: new Date().toISOString(),
      error: error.message,
      versionFamily: node.versionFamily || "unknown",
      versionRelease: node.versionRelease || "unknown",
      remote: node.remote || false,
      docker: node.docker || false
    };

    await db.set(`${node.id}_node`, offlineNode);
    nodeStatusCache.set(node.id, offlineNode);
    return offlineNode;
  }
}

/**
 * Safely deletes an instance and all related data
 */
async function deleteInstance(instance) {
  try {
    validateInstance(instance);

    // Try to delete the instance from the node
    try {
      await axios({
        method: "delete",
        url: `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.ContainerId}`,
        auth: {
          username: "Skyport",
          password: instance.Node.apiKey
        },
        timeout: DEFAULT_TIMEOUT,
        validateStatus: () => true
      });
    } catch (error) {
      if (error.code !== "ECONNREFUSED" && !error.response) {
        log.warn(`Failed to delete instance ${instance.Id} from node:`, error.message);
      }
    }

    // Use transaction-like pattern for data consistency
    const [userInstances, globalInstances] = await Promise.all([
      db.get(`${instance.User}_instances`).catch(() => []),
      db.get("instances").catch(() => [])
    ]);

    const updatedUserInstances = (userInstances || []).filter(
      (obj) => obj.Id !== instance.Id
    );
    const updatedGlobalInstances = (globalInstances || []).filter(
      (obj) => obj.Id !== instance.Id
    );

    await Promise.all([
      db.set(`${instance.User}_instances`, updatedUserInstances),
      db.set("instances", updatedGlobalInstances),
      db.delete(`${instance.Id}_instance`).catch(() => {}),
      db.delete(`${instance.Id}_workflow`).catch(() => {}),
      deleteWorkflowFromFile(instance.Id)
    ]);

    log.info(`Successfully deleted instance ${instance.Id}`);
    return true;
  } catch (error) {
    log.error(`Error deleting instance ${instance.Id}:`, error);
    throw error;
  }
}

/**
 * Deletes workflow from the workflow file
 */
async function deleteWorkflowFromFile(instanceId) {
  try {
    if (!instanceId) {
      throw new Error("Instance ID is required");
    }

    let workflows = {};
    try {
      const data = await fs.readFile(WORKFLOWS_FILE_PATH, "utf8");
      workflows = JSON.parse(data);
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      return; // File doesn't exist, nothing to delete
    }

    if (workflows[instanceId]) {
      delete workflows[instanceId];
      await fs.writeFile(
        WORKFLOWS_FILE_PATH,
        JSON.stringify(workflows, null, 2),
        "utf8"
      );
      log.info(`Deleted workflow for instance ${instanceId} from file`);
    }
  } catch (error) {
    log.error("Error deleting workflow from file:", error);
    throw error;
  }
}

/**
 * Middleware to handle common error responses
 */
function handleErrors(res, req, error, message = "An error occurred") {
  log.error(message, error);
  return res.status(500).render("error", {
    error: message,
    user: req.user,
  });
}

// Admin instances routes
router.get("/admin/instances", isAdmin, async (req, res) => {
  try {
    const [instances, images, rawNodes, users] = await Promise.all([
      db.get("instances").catch(() => []),
      db.get("images").catch(() => []),
      db.get("nodes").catch(() => []),
      db.get("users").catch(() => []),
    ]);

    // Process nodes in parallel with error handling
    const nodes = await Promise.all(
      (rawNodes || []).map(async (id) => {
        try {
          const node = await db.get(`${id}_node`);
          return node ? await checkNodeStatus(node) : null;
        } catch (error) {
          log.error(`Error processing node ${id}:`, error);
          return null;
        }
      })
    );

    // Filter out null nodes and create lookup map
    const validNodes = nodes.filter(Boolean);
    const nodeMap = validNodes.reduce((acc, node) => {
      acc[node.id] = node;
      return acc;
    }, {});

    // Process instances with safe defaults
    const processedInstances = (instances || []).map((instance) => {
      try {
        const node = instance.Node?.id ? nodeMap[instance.Node.id] : null;
        return {
          ...instance,
          Node: node || { name: "Unknown", id: "unknown", status: "Offline" },
          State: instance.State || "unknown",
          suspended: Boolean(instance.suspended)
        };
      } catch (error) {
        log.error(`Error processing instance ${instance.Id}:`, error);
        return {
          ...instance,
          Node: { name: "Error", id: "error", status: "Error" },
          State: "error",
          suspended: false
        };
      }
    });

    res.render("admin/instances", {
      req,
      user: req.user,
      instances: processedInstances,
      images: images || [],
      nodes: validNodes,
      users: users || [],
    });
  } catch (error) {
    handleErrors(res, req, error, "Failed to load instances");
  }
});

router.get("/admin/instances/:id/edit", isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      req.session.error = "Instance ID is required";
      return res.redirect("/admin/instances");
    }

    const [instance, users, images] = await Promise.all([
      db.get(`${id}_instance`).catch(() => null),
      db.get("users").catch(() => []),
      db.get("images").catch(() => []),
    ]);

    if (!instance) {
      req.session.error = "Instance not found";
      return res.redirect("/admin/instances");
    }

    res.render("admin/instance_edit", {
      req,
      user: req.user,
      instance,
      images: images || [],
      users: users || [],
    });
  } catch (error) {
    handleErrors(res, req, error, "Failed to load instance edit page");
  }
});

router.get("/admin/instance/delete/:id", isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      req.session.error = "Instance ID is required";
      return res.redirect("/admin/instances");
    }

    const instance = await db.get(`${id}_instance`).catch(() => null);
    if (!instance) {
      req.session.error = "Instance not found";
      return res.redirect("/admin/instances");
    }

    await deleteInstance(instance);
    logAudit(req.user.userId, req.user.username, "instance:delete", req.ip);
    req.session.success = "Instance deleted successfully";
    res.redirect("/admin/instances");
  } catch (error) {
    log.error("Error deleting instance:", error);
    req.session.error = "Failed to delete instance";
    res.redirect("/admin/instances");
  }
});

router.get("/admin/instances/purge/all", isAdmin, async (req, res) => {
  try {
    const instances = (await db.get("instances")) || [];

    // Delete instances in batches to avoid overwhelming the system
    const BATCH_SIZE = 5;
    for (let i = 0; i < instances.length; i += BATCH_SIZE) {
      const batch = instances.slice(i, i + BATCH_SIZE);
      await Promise.all(
        batch.map((instance) =>
          deleteInstance(instance).catch((error) => {
            log.error(`Error deleting instance ${instance.Id}:`, error);
            return null;
          })
        )
      );
    }

    await db.delete("instances");
    logAudit(req.user.userId, req.user.username, "instances:purge_all", req.ip);
    req.session.success = "All instances purged successfully";
    res.redirect("/admin/instances");
  } catch (error) {
    log.error("Error purging all instances:", error);
    req.session.error = "Failed to purge all instances";
    res.redirect("/admin/instances");
  }
});

router.post("/admin/instances/suspend/:id", isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      req.session.error = "Instance ID is required";
      return res.redirect("/admin/instances");
    }

    const instance = await db.get(`${id}_instance`).catch(() => null);
    if (!instance) {
      req.session.error = "Instance not found";
      return res.redirect("/admin/instances");
    }

    const updatedInstance = { ...instance, suspended: true };
    await db.set(`${id}_instance`, updatedInstance);

    // Update both the instance record and the global instances list
    const [instances] = await Promise.all([
      db.get("instances").catch(() => []),
      db.set(`${id}_instance`, updatedInstance)
    ]);

    const updatedInstances = (instances || []).map((obj) =>
      obj.Id === instance.Id ? { ...obj, suspended: true } : obj
    );

    await db.set("instances", updatedInstances);
    logAudit(req.user.userId, req.user.username, "instance:suspend", req.ip);
    req.session.success = "Instance suspended successfully";
    res.redirect("/admin/instances");
  } catch (error) {
    log.error("Error suspending instance:", error);
    req.session.error = "Failed to suspend instance";
    res.redirect("/admin/instances");
  }
});

router.post("/admin/instances/unsuspend/:id", isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      req.session.error = "Instance ID is required";
      return res.redirect("/admin/instances");
    }

    const instance = await db.get(`${id}_instance`).catch(() => null);
    if (!instance) {
      req.session.error = "Instance not found";
      return res.redirect("/admin/instances");
    }

    const updatedInstance = { ...instance, suspended: false };
    if (updatedInstance["suspended-flagg"]) {
      delete updatedInstance["suspended-flagg"];
    }

    // Update both the instance record and the global instances list
    const [instances] = await Promise.all([
      db.get("instances").catch(() => []),
      db.set(`${id}_instance`, updatedInstance)
    ]);

    const updatedInstances = (instances || []).map((obj) => {
      if (obj.Id === instance.Id) {
        const newObj = { ...obj, suspended: false };
        if (newObj["suspended-flagg"]) delete newObj["suspended-flagg"];
        return newObj;
      }
      return obj;
    });

    await db.set("instances", updatedInstances);
    logAudit(req.user.userId, req.user.username, "instance:unsuspend", req.ip);
    req.session.success = "Instance unsuspended successfully";
    res.redirect("/admin/instances");
  } catch (error) {
    log.error("Error unsuspending instance:", error);
    req.session.error = "Failed to unsuspend instance";
    res.redirect("/admin/instances");
  }
});

module.exports = router;