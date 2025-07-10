const express = require('express');
const axios = require('axios');
const { db } = require('../../handlers/db.js');
const { logAudit } = require('../../handlers/auditlog');
const { v4: uuid } = require('uuid');

const router = express.Router();

async function processInstances() {
  try {
    // Get instances from the database
    const instances = await db.get("instances");

    if (!instances || instances.length === 0) {
      console.log("No instances found.");
      return;
    }

    // Process each instance
    for (const instance of instances) {
      try {
        // Get the current state from the remote server
        const getStateUrl = `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.Id}/states/get`;
        const getStateResponse = await axios.get(getStateUrl, {
          auth: {
            username: "Skyport",
            password: instance.Node.apiKey,
          },
        });

        const newState = getStateResponse.data.state;
        console.log(`State for instance ${instance.Id} is ${newState}`);

        // Update the state on the remote server
        const setStateUrl = `http://${instance.Node.address}:${instance.Node.port}/instances/${instance.Id}/states/set/${newState}`;
        await axios.get(setStateUrl, {}, {
          auth: {
            username: "Skyport",
            password: instance.Node.apiKey,
          },
        });

        console.log(`State for instance ${instance.Id} updated to ${newState}`);

        // Get the instance database and update its state
        const instanceDb = await db.get(`${instance.Id}_instance`);
        if (instanceDb) {
          instanceDb.State = newState;
          await db.set(`${instance.Id}_instance`, instanceDb);
          console.log(`Database updated for instance ${instance.Id}`);
        } else {
          console.log(`No database found for instance ${instance.Id}`);
        }
      } catch (instanceError) {
        console.error(`Error processing instance ${instance.Id}:`, instanceError.message);
      }
    }
  } catch (error) {
    console.error("Error processing instances:", error.message);
  }
}

/**
 * Middleware to verify if the user is an administrator.
 * Checks if the user object exists and if the user has admin privileges. If not, redirects to the
 * home page. If the user is an admin, proceeds to the next middleware or route handler.
 *
 * @param {Object} req - The request object, containing user data.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware or route handler to be executed.
 * @returns {void} Either redirects or proceeds by calling next().
 */
function isAdmin(req, res, next) {
  if (!req.user || req.user.admin !== true) {
    return res.redirect('../');
  }
  next();
}

/**
 * GET /instances/deploy
 * Handles the deployment of a new instance based on the parameters provided via query strings.
 */
router.get('/instances/deploy', isAdmin, async (req, res) => {
  const { image, imagename, memory, disk, cpu, ports, nodeId, name, user, primary, variables } =
    req.query;
  if (!image || !memory || !cpu || !disk || !ports || !nodeId || !name || !user || !primary) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  try {
    const Id = uuid().split('-')[0];
    const node = await db.get(`${nodeId}_node`);
    if (!node) {
      return res.status(400).json({ error: 'Invalid node' });
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
      imagename,
    );
    const response = await axios(requestData);

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
      imagename,
    );

    logAudit(req.user.userId, req.user.username, 'instance:create', req.ip);
    res.status(201).json({
      message: "Container created successfully and added to user's servers",
      containerId: response.data.containerId,
      volumeId: response.data.volumeId,
      State: response.data.state,
    });
  } catch (error) {
    console.error('Error deploying instance:', error);
    res.status(500).json({
      error: 'Failed to create container',
      details: error.response ? error.response.data : 'No additional error info',
    });
  }
});

async function prepareRequestData(image, memory, cpu, ports, name, node, Id, variables, imagename) {
  const rawImages = await db.get('images');
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
      Env: imageData ? imageData.Env : undefined,
      Scripts: imageData ? imageData.Scripts : undefined,
      Memory: memory ? parseInt(memory) : undefined,
      Cpu: cpu ? parseInt(cpu) : undefined,
      ExposedPorts: {},
      PortBindings: {},
      variables,
      AltImages: imageData ? imageData.AltImages : [],
      StopCommand: imageData ? imageData.StopCommand : undefined,
      imageData,
    },
  };

  if (ports) {
    ports.split(',').forEach(portMapping => {
      const [containerPort, hostPort] = portMapping.split(':');

      // Adds support for TCP
      const tcpKey = `${containerPort}/tcp`;
      if (!requestData.data.ExposedPorts[tcpKey]) {
        requestData.data.ExposedPorts[tcpKey] = {};
      }

      if (!requestData.data.PortBindings[tcpKey]) {
        requestData.data.PortBindings[tcpKey] = [{ HostPort: hostPort }];
      }

      // Adds support for UDP
      const udpKey = `${containerPort}/udp`;
      if (!requestData.data.ExposedPorts[udpKey]) {
        requestData.data.ExposedPorts[udpKey] = {};
      }

      if (!requestData.data.PortBindings[udpKey]) {
        requestData.data.PortBindings[udpKey] = [{ HostPort: hostPort }];
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
  disk,
  cpu,
  ports,
  primary,
  name,
  Id,
  imagename,
) {
  const rawImages = await db.get('images');
  const imageData = rawImages.find(i => i.Name === imagename);

  let altImages = imageData ? imageData.AltImages : [];

  const instanceData = {
    Name: name,
    Id,
    Node: node,
    User: userId,
    ContainerId: responseData.containerId,
    VolumeId: Id,
    Memory: parseInt(memory),
    Disk: disk,
    Cpu: parseInt(cpu),
    Ports: ports,
    Primary: primary,
    Image: image,
    AltImages: altImages,
    StopCommand: imageData ? imageData.StopCommand : undefined,
    imageData,
    Env: responseData.Env,
    State: responseData.state,
  };

  const userInstances = (await db.get(`${userId}_instances`)) || [];
  userInstances.push(instanceData);
  await db.set(`${userId}_instances`, userInstances);

  const globalInstances = (await db.get('instances')) || [];
  globalInstances.push(instanceData);
  await db.set('instances', globalInstances);

  await db.set(`${Id}_instance`, instanceData);
}

module.exports = router;
