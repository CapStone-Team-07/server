const { Client } = require('ssh2');
const fs = require('fs');

exports.containAgent = (req, res) => {
    const { action } = req.params;
    const { agentId, agentIP } = req.body;

    const conn = new Client();
    const command = `powershell.exe -ExecutionPolicy Bypass -File C:\\SecurityScripts\\containment.ps1 -Action ${action} -AllowedManagementIP ${process.env.MANAGEMENT_IP}`;

    conn.on('ready', () => {
        conn.exec(command, (err, stream) => {
            if (err) {
                return res.status(500).json({ success: false, error: err.message });
            }

            let output = '';
            stream.on('data', data => output += data.toString());

            stream.on('close', code => {
                conn.end();
                res.status(200).json({
                    success: code === 0,
                    output,
                    exitCode: code
                });
            });
        });
    });

    conn.on('error', (err) => {
        return res.status(500).json({ success: false, error: `SSH connection error: ${err.message}` });
    });

    conn.connect({
        host: agentIP,
        username: process.env.SSH_USERNAME,
        privateKey: fs.readFileSync(process.env.SSH_PRIVATE_KEY_PATH)
    });
};
