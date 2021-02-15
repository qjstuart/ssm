import express from 'express';
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import https from 'https';
import fs from 'fs';
import helmet from 'helmet';
import { vaultExists, loadVault, createApplicationKey} from './middleware/vault.js';
import bodyParser from 'body-parser';


// configure server
const options = {
    key: fs.readFileSync("./www/localhost.key"),
    cert: fs.readFileSync("./www/localhost.crt")
};
const PORT = process.env.PORT || 3000; 
const app = express();

// force every request to be HTTPS
app.use(helmet());

// define variable for CWD
const __dirname = dirname(fileURLToPath(import.meta.url));

// use middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(vaultExists); 

// SSM variables
let vault = {}


app.post('/admin/applicationkeys', (req, res) => {
    createApplicationKey(req, res);

});













https.createServer(options, app).listen(PORT, () => console.log(`[+] Server started on port ${PORT}.`));















// app.get('/', (req, res) => {
//     console.log("[+] Received: " + JSON.stringify(req.body));
    
//     let jsonString = fs.readFileSync('./vault.json');
//     let vault = JSON.parse(jsonString);

//     vault.applicationkeys = {
//       Facebook: {
//         name: "Facebook",
//         algorithm: "DES",
//         iv: "blabla",
//       },
//       Whatsapp: {
//         name: "Whatsapp",
//         algorithm: "SHA256",
//         iv: "no",
//       },
//       IG: {
//         name: "IG",
//         algorithm: "AES",
//         iv: "sure",
//       }     
//     };

//     vault.applicationkeys["test"] = {algorithm: "AES", iv:2}

//     // vault['keyEncryptionKey'].push(applicationkeys);
//     jsonString = JSON.stringify(vault);

//     fs.writeFileSync('./vault.json', jsonString);

//     res.end();
// });

