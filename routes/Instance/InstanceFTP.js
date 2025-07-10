const express = require('express');
const router = express.Router();
const axios = require('axios');
const { db } = require('../../handlers/db.js');
const { isUserAuthorizedForContainer } = require('../../utils/authHelper');
const { loadPlugins } = require('../../plugins/loadPls.js');
const path = require('path');

const plugins = loadPlugins(path.join(__dirname, '../../plugins'));

router.get("/instance/:id/ftp", async (req, res) => {
    try {
        // Authentication and validation checks
        if (!req.user) {
            return res.redirect('/');
        }

        const { id } = req.params;
        if (!id) {
            return res.redirect('../../../../instances');
        }

        // Fetch instance data
        const instance = await db.get(id + '_instance').catch(err => {
            console.error('Failed to fetch instance:', err);
            return null;
        });

        if (!instance) {
            return res.redirect('../../../../instances');
        }

        // Check instance suspension status
        if (instance.suspended === true) {
            return res.redirect(`../../instance/${id}/suspended`);
        }

        // Authorization check
        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).send('Unauthorized access to this instance.');
        }

        // Validate volume and node configuration
        if (!instance.VolumeId) {
            return res.status(400).send('Instance has no volume attached.');
        }

        if (!instance.Node || !instance.Node.address || !instance.Node.port || !instance.Node.apiKey) {
            return res.status(500).send('Invalid instance node configuration');
        }

        // Make request to node
        const requestData = {
            method: 'get',
            url: `http://${instance.Node.address}:${instance.Node.port}/ftp/info/${instance.VolumeId}`,
            auth: {
                username: 'Skyport',
                password: instance.Node.apiKey
            },
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            timeout: 5000 // 5 second timeout
        };

        const [settings, response] = await Promise.all([
            db.get('settings'),
            axios(requestData)
        ]);

        const allPluginData = Object.values(plugins).map(plugin => plugin.config);
        const logindata = response.data || [];

        res.render('instance/ftp', {
            req,
            logindata,
            instance,
            user: req.user,
            name: await db.get('name') || 'HydraPanel',
            logo: await db.get('logo') || false,
            addons: {
                plugins: allPluginData
            },
            settings: settings || {}
        });

    } catch (error) {
        console.error('FTP route error:', error);

        let errorMessage = 'An unexpected error occurred';
        let statusCode = 500;

        if (error.response) {
            // Axios response error
            errorMessage = error.response.data.message || 'Node request failed';
            statusCode = error.response.status || 500;
        } else if (error.request) {
            // Axios request was made but no response
            errorMessage = 'Connection to node failed';
        } else if (error.code === 'ECONNABORTED') {
            errorMessage = 'Node request timed out';
        }

        res.status(statusCode).send({ message: errorMessage });
    }
});

module.exports = router;