const express = require('express');
const router = express.Router();
const { db } = require('../../handlers/db.js');
const { isUserAuthorizedForContainer } = require('../../utils/authHelper');
const { editFile } = require('../../utils/fileHelper');

router.post("/instance/:id/files/edit/:filename", async (req, res) => {
    try {
        // Authentication check
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        // Parameter validation
        const { id, filename } = req.params;
        const { content } = req.body;

        if (!id || !filename || content === undefined) {
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        // Get instance from database
        const instance = await db.get(`${id}_instance`);
        if (!instance) {
            return res.status(404).json({ error: 'Instance not found' });
        }

        // Authorization check
        const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
        if (!isAuthorized) {
            return res.status(403).json({ error: 'Unauthorized access to this instance' });
        }

        // Instance status check
        if (instance.suspended) {
            return res.status(403).redirect('../../instances?err=SUSPENDED');
        }

        // Ensure suspended flag exists (backward compatibility)
        if (instance.suspended === undefined) {
            instance.suspended = false;
            await db.set(`${id}_instance`, instance);
        }

        // Node configuration validation
        if (!instance.Node?.address || !instance.Node?.port) {
            return res.status(500).json({ error: 'Invalid instance node configuration' });
        }

        // File path validation
        const filePath = req.query.path || '';
        if (typeof filePath !== 'string') {
            return res.status(400).json({ error: 'Invalid path parameter' });
        }

        // Edit file operation
        const result = await editFile(instance, filename, content, filePath);
        return res.json(result);

    } catch (error) {
        console.error('Error editing file:', error);
        
        if (error.response) {
            return res.status(error.response.status || 500).json({
                error: error.response.data || 'Failed to edit file'
            });
        }
        
        return res.status(500).json({ 
            error: 'Internal server error',
            details: error.message 
        });
    }
});

module.exports = router;
