const express = require('express');
const router = express.Router();
const axios = require('axios');
const { db } = require('../../handlers/db.js');
const { isUserAuthorizedForContainer } = require('../../utils/authHelper');
const { loadPlugins } = require('../../plugins/loadPls.js');
const path = require('path');

const plugins = loadPlugins(path.join(__dirname, '../../plugins'));

/**
 * GET /instance/:id/archives
 * Lists all archives for a specific instance and renders them on an EJS page.
 */
router.get("/instance/:id/archives", async (req, res) => {
    if (!req.user) {
        return res.redirect('/');
    }

    const { id } = req.params;
    if (!id) {
        return res.redirect('/instances');
    }

    try {
        const instance = await db.get(`${id}_instance`);

        if (!instance || !instance.ContainerId) {
            return res.redirect('/instances');
        }

        if (instance.suspended === true) {
            return res.redirect('../../instances?err=SUSPENDED');
        }

        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        if (instance.Node && instance.Node.address && instance.Node.port) {
            const RequestData = {
                method: 'get',
                url: `http://${instance.Node.address}:${instance.Node.port}/archive/${instance.ContainerId}/archives`,
                auth: {
                    username: 'Skyport',
                    password: instance.Node.apiKey
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            try {
                const response = await axios(RequestData);
                const archives = response.data.archives || [];

                const allPluginData = Object.values(plugins).map(plugin => plugin.config);
                const settings = await db.get('settings');

                res.render('instance/archives', {
                    req,
                    user: req.user,
                    instance,
                    name: await db.get('name') || 'HydraPanel',
                    logo: await db.get('logo') || false,
                    archives,
                    settings,
                    addons: {
                        plugins: allPluginData
                    },
                });
            } catch (error) {
                const errorMessage = error.response?.data?.message || 'Connection to node failed.';
                console.error('Error fetching archives from node:', errorMessage);
                return res.status(500).send({ message: errorMessage });
            }
        } else {
            res.status(500).send('Invalid instance node configuration');
        }
    } catch (err) {
        console.error('Error fetching instance or settings:', err);
        res.status(500).send('Server error');
    }
});

/**
 * GET /instance/:id/archives/download/:archiveName
 * Downloads a specific archive file
 */
router.get('/instance/:id/archives/download/:archiveName', async (req, res) => {
    if (!req.user) {
        return res.redirect('/');
    }

    const { id, archiveName } = req.params;

    try {
        const instance = await db.get(`${id}_instance`);

        if (!instance || !instance.ContainerId) {
            return res.status(404).send('Instance not found');
        }

        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        if (instance.suspended === true) {
            return res.status(403).send('Instance is suspended');
        }

        if (!instance.Node || !instance.Node.address || !instance.Node.port) {
            return res.status(500).send('Invalid node configuration');
        }

        const downloadUrl = `http://Skyport:${instance.Node.apiKey}@${instance.Node.address}:${instance.Node.port}/archive/${instance.ContainerId}/archives/download/${archiveName}`;

        // Redirect to the node's download endpoint
        res.redirect(downloadUrl);

    } catch (err) {
        console.error('Error downloading archive:', err);
        res.status(500).send('Server error');
    }
});

router.post('/instance/:id/archives/create', async (req, res) => {
    const { id } = req.params;
    if (!req.user) {
        return res.redirect('/');
    }

    try {
        const instance = await db.get(`${id}_instance`);

        if (!instance || !instance.ContainerId) {
            return res.redirect('/instances');
        }

        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        if (instance.suspended === true) {
            return res.redirect('../../instances?err=SUSPENDED');
        }

        const RequestData = {
            method: 'post',
            url: `http://Skyport:${instance.Node.apiKey}@${instance.Node.address}:${instance.Node.port}/archive/${instance.ContainerId}/archives/${instance.VolumeId}/create`,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const response = await axios(RequestData);
        if (response.status === 200) {
            res.redirect('/instance/' + id + '/archives');
        } else {
            res.status(500).send('Failed to create archive');
        }
    } catch (error) {
        console.error('Error creating archive:', error);
        res.status(500).send(error.response?.data?.message || 'Failed to create archive');
    }
});

router.post('/instance/:id/archives/delete/:archiveName', async (req, res) => {
    const { id, archiveName } = req.params;
    if (!req.user) {
        return res.redirect('/');
    }

    try {
        const instance = await db.get(`${id}_instance`);

        if (!instance || !instance.ContainerId) {
            return res.redirect('/instances');
        }

        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        if (instance.suspended === true) {
            return res.redirect('../../instances?err=SUSPENDED');
        }

        const RequestData = {
            method: 'post',
            url: `http://Skyport:${instance.Node.apiKey}@${instance.Node.address}:${instance.Node.port}/archive/${instance.ContainerId}/archives/delete/${archiveName}`,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const response = await axios(RequestData);
        if (response.status === 200) {
            res.redirect('/instance/' + id + '/archives');
        } else {
            res.status(500).send('Failed to delete archive');
        }
    } catch (error) {
        console.error('Error deleting archive:', error);
        res.status(500).send(error.response?.data?.message || 'Failed to delete archive');
    }
});

router.post('/instance/:id/archives/rollback/:archiveName', async (req, res) => {
    const { id, archiveName } = req.params;
    if (!req.user) {
        return res.redirect('/');
    }

    try {
        const instance = await db.get(`${id}_instance`);

        if (!instance || !instance.ContainerId) {
            return res.redirect('/instances');
        }

        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        if (instance.suspended === true) {
            return res.redirect('../../instances?err=SUSPENDED');
        }

        const RequestData = {
            method: 'post',
            url: `http://Skyport:${instance.Node.apiKey}@${instance.Node.address}:${instance.Node.port}/archive/${instance.ContainerId}/archives/rollback/${instance.VolumeId}/${archiveName}`,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const response = await axios(RequestData);
        if (response.status === 200) {
            res.redirect('/instance/' + id + '/archives');
        } else {
            res.status(500).json({
                error: response.data?.error || 'Failed to rollback archive'
            });
        }
    } catch (error) {
        console.error('Error rolling back archive:', error);
        res.status(500).json({
            error: error.response?.data?.error || 'Failed to rollback archive'
        });
    }
});

module.exports = router;