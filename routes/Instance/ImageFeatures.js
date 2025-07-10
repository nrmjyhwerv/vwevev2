const express = require('express');
const router = express.Router();
const { db } = require('../../handlers/db.js');
const { isUserAuthorizedForContainer } = require('../../utils/authHelper');
const { createFile, fetchFiles } = require('../../utils/fileHelper');

router.post("/instance/:id/imagefeatures/eula", async (req, res) => {
    if (!req.user) return res.redirect('/');

    const { id } = req.params;

    const instance = await db.get(id + '_instance').catch(err => {
        console.error('Failed to fetch instance:', err);
        return null;
    });

    if (!instance || !instance.VolumeId) return res.redirect('../instances');

    const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
    if (!isAuthorized) {
        return res.status(403).send('Unauthorized access to this instance.');
    }


    if(!instance.suspended) {
        instance.suspended = false;
        db.set(id + '_instance', instance);
    }

      if(instance.suspended === true) {
         return res.redirect('../../instances?err=SUSPENDED');
    }
        createFile(instance, 'eula.txt', 'eula=true');

    res.status(200).send('OK');

});

router.get("/instance/:id/imagefeatures/cracked", async (req, res) => {
    if (!req.user) return res.redirect('/');

    const { id } = req.params;

    const instance = await db.get(id + '_instance').catch(err => {
        console.error('Failed to fetch instance:', err);
        return null;
    });

    if (!instance || !instance.VolumeId) return res.redirect('../instances');

    const isAuthorized = await isUserAuthorizedForContainer(req.user.userId, instance.Id);
    if (!isAuthorized) {
        return res.status(403).send('Unauthorized access to this instance.');
    }


    if(!instance.suspended) {
        instance.suspended = false;
        db.set(id + '_instance', instance);
    }

      if(instance.suspended === true) {
         return res.redirect('../../instances?err=SUSPENDED');
    }
    const serverport = instance.Ports.split(':')[1];
    const now = new Date();

// Get the year, month, day, hours, minutes, and seconds
const year = now.getFullYear();
const month = (now.getMonth() + 1).toString().padStart(2, '0'); // Months are 0-indexed
const day = now.getDate().toString().padStart(2, '0');
const hours = now.getHours().toString().padStart(2, '0');
const minutes = now.getMinutes().toString().padStart(2, '0');
const seconds = now.getSeconds().toString().padStart(2, '0');

// Combine into a formatted string
const formattedDateTime = `#${day} ${month} ${hours}:${minutes}:${seconds} UTC ${year}`;


    console.log(`Successfully Enabled Cracked for ${id} with Port ${serverport}`)
    const content = `
#Minecraft server properties
${formattedDateTime}
accepts-transfers=false
allow-flight=false
allow-nether=true
broadcast-console-to-ops=true
broadcast-rcon-to-ops=true
bug-report-link=
debug=false
difficulty=easy
enable-command-block=false
enable-jmx-monitoring=false
enable-query=false
enable-rcon=false
enable-status=true
enforce-secure-profile=true
enforce-whitelist=false
entity-broadcast-range-percentage=100
force-gamemode=false
function-permission-level=2
gamemode=survival
generate-structures=true
generator-settings={}
hardcore=false
hide-online-players=false
initial-disabled-packs=
initial-enabled-packs=vanilla
level-name=world
level-seed=
level-type=default
log-ips=true
max-build-height=256
max-chained-neighbor-updates=1000000
max-players=20
max-tick-time=60000
max-world-size=29999984
motd=A Minecraft Server
network-compression-threshold=256
online-mode=false
op-permission-level=4
player-idle-timeout=0
prevent-proxy-connections=false
pvp=true
query.port=25565
rate-limit=0
rcon.password=
rcon.port=25575
region-file-compression=deflate
require-resource-pack=false
resource-pack=
resource-pack-id=
resource-pack-prompt=
resource-pack-sha1=
server-ip=
server-port=${serverport}
simulation-distance=10
snooper-enabled=true
spawn-animals=true
spawn-monsters=true
spawn-npcs=true
spawn-protection=16
sync-chunk-writes=true
text-filtering-config=
use-native-transport=true
view-distance=10
white-list=false

    `

    createFile(instance, 'server.properties', content);

    res.redirect('/instance/'+ id);
});


module.exports = router;
