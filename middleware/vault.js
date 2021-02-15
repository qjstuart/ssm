import fs, { write } from 'fs'
import passwordValidator from 'password-validator'
import crypto from 'crypto'
import Key from './key.js' 

// Define SSM global variables
const vaultPath = './vault.json'
let saltMK1 = null
let saltMK2 = null
let saltKEK1 = null
let saltKEK2 = null
let MK1 = null
let MK2 = null
let KEK = null
let KEK1 = null
let KEK2 = null
let KEKEncMK1 = null
let KEKMacMK2 = null
let vault = {}


const vaultExists = (req, res, next) => {
    if (!fs.existsSync(vaultPath)) {
        console.log("[+] No vault file found. Creating...")
        setupKeys(req, res)
        next()
    }
    else{
        console.log("[+] Existing vault file found.")
        loadVault(req, res)
        next()
    }
}

const setupKeys = (req, res) => {

    // Validate the provided first-time master key
    validateMK(req,res)

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltMK1 = crypto.randomBytes(16).toString('hex')
    saltMK2 = crypto.randomBytes(16).toString('hex')

    // Derive MK1 and MK2 as hex from master key
    MK1 = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK1, 100000, 32, 'sha512').toString('hex')
    MK2 = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK2, 100000, 32, 'sha512').toString('hex')
    
    // Generate random KEK as hex
    KEK = crypto.randomBytes(32).toString('hex')

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltKEK1 = crypto.randomBytes(16).toString('hex')
    saltKEK2 = crypto.randomBytes(16).toString('hex')

    // Derive KEK1 and KEK2 as crypto object from KEK (can be converted to several types)
    KEK1 = crypto.pbkdf2Sync(KEK, saltKEK1, 100000, 32, 'sha512')
    KEK2 = crypto.pbkdf2Sync(KEK, saltKEK1, 100000, 32, 'sha512')

}

const validateMK = (req, res) => {
    let schema = new passwordValidator()
    schema
    .is().min(16)
    .is().max(100)
    .has().lowercase()
    .has().digits()
    .has().not().spaces()

    if (!schema.validate(JSON.stringify(req.body.MK_adminA)) || !schema.validate(JSON.stringify(req.body.MK_adminA))) {
        res.status(406).send("[-] One or both parts of the MK are not strong enough.")
    }
}



const loadVault = (req, res) => {

    console.log("ENETERED loadVault()")
    // // Read vault file synchronously
    // let jsonString = fs.readFileSync(vaultPath)

    // try {
    //     // Parse vault file
    //     vault = JSON.parse(jsonString) 

    //     // set global variables and return vault object

    //     deriveMK1MK2(req, res)
    //     KEKEncMK1 = vault.KEKEncMK1
    //     KEKMacMK2 = vault.KEKMacMK2

    //     KEK = CryptoJS.AES.decrypt(KEKEncMK1, MK1)
    //     console.log(KEK)

    //     return vault

    // } catch (err) {
    //     res.status(500).send("[-] Error loading from vault: " + err)
    // }
}





const createApplicationKey = (req, res) => {

    // Create a new Key object
    const AK = new Key(req.body.name, req.body.algorithm, req.body.mode, req.body.padding, req.body.keysize, req.body.lifetime, req.body.autorotate)
    
    if (req.body.algorithm == 'AES' && req.body.mode == 'CBC' && req.body.keysize == "256") {


        let value = crypto.randomBytes(32).toString('hex')     // Application key is a hex value
        console.log("Secret password: " + value)

        AK.iv = crypto.randomBytes(16)

        let cipher = crypto.createCipheriv('aes-256-cbc', KEK1, AK.iv)
        AK.encryptedvalue = cipher.update(value, 'hex', 'hex')
        AK.encryptedvalue += cipher.final('hex')

        console.log("Encrypted: " + AK.encryptedvalue)

        let decipher = crypto.createDecipheriv('aes-256-cbc', KEK1, AK.iv)
        let decrypted = decipher.update(AK.encryptedvalue, 'hex', 'hex')
        decrypted += decipher.final('hex')

        console.log("Decrypted: " + decrypted)

        res.status(200).send("OK")
        



    }

}





export { vaultExists, validateMK, setupKeys, loadVault, createApplicationKey }