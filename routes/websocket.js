var WebSocket = require('ws');
var DB = require('../classes/database');

var ws = new WebSocket.Server({ clientTracking: true, noServer: true});

ws.on('connection', function(client, request) {
    var projects = request.session.projects;
    for (let i=0; i<projects.length; i++)
    {
        DB.UsersMap.set(projects[i], client);
    }
    client.on('message', function(message) {
        try
        {
            var data = JSON.parse(message);
            if (data.cmd === "getResult" && data.id && projects.includes(data.id))
            {
                if (data.id in DB.vulns) {
                    var dataToSend = {"status": "finished", "vulns": DB.vulns[data.id]};
                    client.send(JSON.stringify(dataToSend));
                }
            } else 
            {
                console.log(`client sent an invalid request: ${data}`);
            }
        } catch(e)
        {
            console.log(e);
            console.log('Invalid Json');
            client.send('401');
        }
    });

    client.on('close', function() {
        for (let i=0; i< projects.length; i++)
        {
            console.log(`client: ${projects[i]} closed the connection`);
            DB.UsersMap.delete(projects[i]);
        }
    })
});


module.exports = ws;