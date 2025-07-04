const { Client } = require('ssh2');
const fs = require('fs');

exports.containAgent = (req, res) => {
    const { agentId, agentIP } = req.body;

    const conn = new Client();
    let responseSent = false;
    console.log(`Agent with ID: ${agentId} at IP: ${agentIP}`);
    console.log(`Using management IP: ${process.env.MANAGEMENT_IP}`);

    const command = `powershell.exe -ExecutionPolicy Bypass -File C:\\SecurityScripts\\containment.ps1 -Action isolate -AllowedManagementIP ${process.env.MANAGEMENT_IP}`;

    conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
            if (err) {
                if (!responseSent) {
                    responseSent = true;
                    res.status(500).json({ success: false, error: err.message });
                }
                conn.end(); // close connection if error
                return;
            }

            let output = '';
            stream.on('data', data => output += data.toString());

            stream.on('close', code => {
                conn.end();
                if (!responseSent) {
                    responseSent = true;
                    res.status(200).json({
                        success: code === 0,
                        output,
                        exitCode: code
                    });
                }
            });

            stream.stderr.on('data', data => {
                output += `STDERR: ${data.toString()}`;
            });
        });
    });

    conn.on('error', (err) => {
        if (!responseSent) {
            responseSent = true;
            res.status(500).json({ success: false, error: `SSH connection error: ${err.message}` });
        }
    });

    conn.connect({
        host: agentIP,
        username: process.env.SSH_USERNAME,
        privateKey: fs.readFileSync(process.env.SSH_PRIVATE_KEY_PATH)
    });
};

exports.restoreAgent = (req, res) => {
    const { agentId, agentIP } = req.body;
    console.log('restoreing')
    const conn = new Client();
    let responseSent = false;
    console.log(`Agent with ID: ${agentId} at IP: ${agentIP}`);
    // console.log(`Using management IP: ${process.env.MANAGEMENT_IP}`);

    const command = `powershell.exe -ExecutionPolicy Bypass -File C:\\SecurityScripts\\containment.ps1 -Action restore`;

    conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
            if (err) {
                if (!responseSent) {
                    responseSent = true;
                    res.status(500).json({ success: false, error: err.message });
                }
                conn.end(); // close connection if error
                return;
            }

            let output = '';
            stream.on('data', data => output += data.toString());

            stream.on('close', code => {
                conn.end();
                if (!responseSent) {
                    responseSent = true;
                    res.status(200).json({
                        success: code === 0,
                        output,
                        exitCode: code
                    });
                }
            });

            stream.stderr.on('data', data => {
                output += `STDERR: ${data.toString()}`;
            });
        });
    });

    conn.on('error', (err) => {
        if (!responseSent) {
            responseSent = true;
            res.status(500).json({ success: false, error: `SSH connection error: ${err.message}` });
        }
    });

    conn.connect({
        host: agentIP,
        username: process.env.SSH_USERNAME,
        privateKey: fs.readFileSync(process.env.SSH_PRIVATE_KEY_PATH)
    });
};


exports.containAgentStatus = (req, res) => {
    const { agentId, agentIP } = req.body;

    const conn = new Client();
    let responseSent = false;
    console.log(`Agent with ID: ${agentId} at IP: ${agentIP}`);
    console.log(`Using management IP: ${process.env.MANAGEMENT_IP}`);

    const command = `powershell.exe -ExecutionPolicy Bypass -File C:\\SecurityScripts\\containment.ps1 -Action status`;

    conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
            if (err) {
                if (!responseSent) {
                    responseSent = true;
                    res.status(500).json({ success: false, error: err.message });
                }
                conn.end(); // close connection if error
                return;
            }

            let output = '';
            stream.on('data', data => output += data.toString());

            stream.on('close', code => {
                conn.end();
                if (!responseSent) {
                    responseSent = true;
                    res.status(200).json({
                        success: code === 0,
                        output,
                        exitCode: code
                    });
                }
            });

            stream.stderr.on('data', data => {
                output += `STDERR: ${data.toString()}`;
            });
        });
    });

    conn.on('error', (err) => {
        if (!responseSent) {
            responseSent = true;
            res.status(500).json({ success: false, error: `SSH connection error: ${err.message}` });
        }
    });

    conn.connect({
        host: agentIP,
        username: process.env.SSH_USERNAME,
        privateKey: fs.readFileSync(process.env.SSH_PRIVATE_KEY_PATH)
    });
};