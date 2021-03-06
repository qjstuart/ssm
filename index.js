import express from 'express'
import { dirname } from 'path'
import { fileURLToPath } from 'url'
import https from 'https'
import fs from 'fs'
import helmet from 'helmet'
import { vaultExists, createApplicationKey, changeMasterKey, rotateKeyEncryptionKey, getApplicationKeyInfo, getApplicationKeysInfo, updateApplicationKey, writeVault, clientEncrypt, clientDecrypt} from './src/vault.js'
import bodyParser from 'body-parser'
import responseTime from 'response-time'
import colors from 'colors'
import { performance } from 'perf_hooks'


// Define variable for CWD
const __dirname = dirname(fileURLToPath(import.meta.url))

// Configure and set up server
const options = {
    // key: fs.readFileSync('./www/localhost.key'),
    // cert: fs.readFileSync('./www/localhost.crt'),
    key: fs.readFileSync('./www/server-key.pem'),
    cert: fs.readFileSync('./www/server-crt.pem'),
    requestCert: true,
    rejectUnauthorized: false,
	ca: [fs.readFileSync('./www/ca-crt.pem')]
}
const PORT = process.env.PORT || 3000 
const app = express()

// Use middleware
app.use(bodyParser.urlencoded({ extended: true }))
app.use(helmet()) // Force every request to be HTTPS
// app.use(responseTime((req, res, time) => { console.log('Operation completed: ' + colors.yellow(time + ' ms')) })) // Log response time for each request

// Set view engine
app.set('view engine', 'ejs')

let KEK = null
let KEK1 = null
let KEK2 = null


// SSM admin main menu
app.get('/', (req, res) => {
    res.render('ssm')
})

// Return create_application_key form 
app.get('/admin/createapplicationkey', (req, res) => {
    res.render('create_application_key')
})
// Handle create_application_key form submission
app.post('/admin/createapplicationkey', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    createApplicationKey(req, res)    
    writeVault(res)
    console.log("KEK: " + KEK.value)
})


// Return rotate_key_encryption_key form
app.get('/admin/rotatekeyencryptionkey', (req, res) => {
    res.render('rotate_key_encryption_key')
})
// Handle rotate_key_encryption_key form submission
app.post('/admin/rotatekeyencryptionkey', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    rotateKeyEncryptionKey(req, res)
    writeVault(res)
})


// Return change_master_key form
app.get('/admin/masterkey', (req, res) => {
    res.render('change_master_key')
})
// Handle change_master_key form submission
app.post('/admin/masterkey', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    changeMasterKey(req, res)
    writeVault()
})


// Return get_application_key_info form
app.get('/admin/getapplicationkeyinfo', (req, res) => {
    res.render('get_application_key_info')
})
// Handle get_application_key_info form submission
app.post('/admin/getapplicationkeyinfo', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    getApplicationKeyInfo(req, res)
})


// Return get_application_keys_info form
app.get('/admin/getapplicationkeysinfo', (req, res) => {
    res.render('get_application_keys_info')
})
// Handle get_application_keys_info form
app.post('/admin/getapplicationkeysinfo', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    getApplicationKeysInfo(req, res)
})


// Return update_application_key form
app.get('/admin/updateapplicationkey', (req, res) => {
    res.render('update_application_key')
})
// Handle update_application_key form
app.post('/admin/updateapplicationkey', (req, res) => {
    [KEK, KEK1, KEK2] = vaultExists(req, res)
    updateApplicationKey(req, res)
})




app.get('/client', (req, res) => {
	const cert = req.socket.getPeerCertificate();
	if (!req.client.authorized) {
		return res.status(401).send('Invalid client certificate authentication.')
    }  
    if (cert.subject) {
       console.log(cert.subject.CN);
   }
})

// Application client encrypt feature
app.get('/client/encrypt', (req, res) => {
    res.render('client_encrypt')
})
app.post('/client/encrypt', (req, res) => {
    let t0 = performance.now()
    clientEncrypt(req, res, KEK, KEK1, KEK2)
    let t1 = performance.now()
    console.log(colors.yellow('Encryption time (ms): ' + (t1-t0)))   
})


// Application client decrypt feature
app.get('/client/decrypt', (req, res) => {
    res.render('client_decrypt')
})
app.post('/client/decrypt', (req, res) => {
    let t0 = performance.now()
    clientDecrypt(req, res, KEK, KEK1, KEK2)
    let t1 = performance.now()
    console.log(colors.yellow('Decryption time (ms): ' + (t1-t0)))   
})




https.createServer(options, app).listen(PORT, () => console.log(`[+] Server started on port ${PORT}.`))