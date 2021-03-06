import fs, { write } from 'fs'
import passwordValidator from 'password-validator'
import crypto from 'crypto'
import { Key } from './key.js' 
import colors from 'colors'

// Define SSM global variables
const vaultPath = './vault.json'
let saltMK1 = null
let saltMK2 = null
let saltKEK1 = null
let saltKEK2 = null
let MK1 = new Key()
let MK2 = new Key()
let KEK = new Key()
let KEK1 = new Key()
let KEK2 = new Key()
let KEKEncMK1 = null
let KEKMacMK2 = null
let vault = {}
let applicationkeys = []
let applicationkeysEncKEK1 = null
let applicationkeysMacKEK2 = null


const vaultExists = (req, res) => {
    if (!fs.existsSync(vaultPath)) {
        console.log("[+] No vault file found. Setting up keys...")
        setupKeys(req, res)
        return [KEK, KEK1, KEK2]
    }
    else{
        console.log("[+] Existing vault file found. Decrypting...")
        loadVault(req, res)
        return [KEK, KEK1, KEK2]
    }
}

const setupKeys = (req, res) => {

    // Validate the provided first-time master key
    validateMK(req, res, 0)

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltMK1 = crypto.randomBytes(16).toString('hex')
    saltMK2 = crypto.randomBytes(16).toString('hex')

    // Derive MK1 and MK2 values and generate random MK1 IV
    MK1.value = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK1, 100000, 32, 'sha512')
    MK1.iv = crypto.randomBytes(16)

    MK2.value = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK2, 100000, 32, 'sha512')

    // Create KEK Key object. Generate random hex value and random IV
    KEK.value = crypto.randomBytes(32).toString('hex')

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltKEK1 = crypto.randomBytes(16).toString('hex')
    saltKEK2 = crypto.randomBytes(16).toString('hex')

    // Derive KEK1 and KEK2 and generate random KEK1 IV
    KEK1.value = crypto.pbkdf2Sync(KEK.value, saltKEK1, 100000, 32, 'sha512')
    KEK1.iv = crypto.randomBytes(16)

    KEK2.value = crypto.pbkdf2Sync(KEK.value, saltKEK2, 100000, 32, 'sha512')
}

const validateMK = (req, res, changeMK) => {
    let schema = new passwordValidator()
    schema
    .is().min(16)
    .is().max(100)
    .has().lowercase()
    .has().digits()
    .has().not().spaces()

    // Validate provided 2-part MK on initial vault creation
    if (changeMK == 0) {
        if (!schema.validate(JSON.stringify(req.body.MK_adminA)) || !schema.validate(JSON.stringify(req.body.MK_adminA))) {
            res.status(406).send("[-] One or both parts of the MK are not strong enough. Each part must be 16-100 characters in length \n and must be alphanumeric with no spaces.")
        }
    }
    // Validate new 2-part MK on CHANGE_MASTER_KEY
    if (changeMK == 1) {
        if (!schema.validate(JSON.stringify(req.body.MK_adminA_new)) || !schema.validate(JSON.stringify(req.body.MK_adminA_new))) {
            res.status(406).send("[-] One or both parts of the MK are not strong enough. Each part must be 16-100 characters in length \n and must be alphanumeric with no spaces.")
        }
    }

    
}

const isUniqueName = (req) => {
    let uniqueName = true
    applicationkeys.forEach((element) => {
        if (element.name == req.body.name) {
            uniqueName = false
        }
    })
    return uniqueName
}

const loadVault = (req, res) => {

    // Attempt to read and parse vault file synchronously
    try {
        let jsonString = fs.readFileSync(vaultPath)
        vault = JSON.parse(jsonString)
    }
    catch (err) {
        res.status(500).send("[-] Error loading from vault: " + err)
    }

    // Populate SSM global variables
    KEKEncMK1 = vault.KeyEncryptionKeyEncMK1
    KEKMacMK2 = vault.KeyEncryptionKeyMacMK2
    applicationkeysEncKEK1 = vault.ApplicationKeysEncKEK1
    applicationkeysMacKEK2 = vault.ApplicationKeysMacKEK2
    saltMK1 = vault.saltMK1
    saltMK2 = vault.saltMK2
    saltKEK1 = vault.saltKEK1
    saltKEK2 = vault.saltKEK2
    KEK1.iv = vault.ivKEK1
    MK1.iv = vault.ivMK1
    MK1.value = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK1, 100000, 32, 'sha512')
    MK2.value = crypto.pbkdf2Sync((req.body.MK_adminA + req.body.MK_adminB), saltMK2, 100000, 32, 'sha512')

    // Decrypt KEK.value and set it as SSM global variable if mac succeeds 
    decryptAndMacKeyEncryptionKey(res)
    // Derive KEK1.value and KEK2.value
    KEK1.value = crypto.pbkdf2Sync(KEK.value, saltKEK1, 100000, 32, 'sha512')
    KEK2.value = crypto.pbkdf2Sync(KEK.value, saltKEK2, 100000, 32, 'sha512')

    // Decrypt application keys list and set it as SSM global variable if mac succeeds
    decryptAndMacApplicationKeysList(res)
}

const decryptAndMacKeyEncryptionKey = (res) => {

    // Decrypt KEK
    let decipher = crypto.createDecipheriv('aes-256-cbc', MK1.value, Buffer.from(MK1.iv, 'hex'))
    let decrypted = null
    try{
        decrypted = decipher.update(KEKEncMK1, 'hex', 'hex')
        decrypted += decipher.final('hex')
    }
    catch (err) {
        // Stop admin request if decryption fails
        res.status(401).send('[-] KEK decryption failed. Check that the 2-part master key is correct, and that vault has not been tampered with.') 
    }

    // Create hmac of KEK.value
    let hmac = crypto.createHmac('sha256', MK2.value, 'hex')
    hmac.update(decrypted)

    // If newly generated hmac != hmac retrieved from vault, vault has been tampered with! 
    if (hmac.digest('hex') != KEKMacMK2) {
        res.status(401).send('[-] KEK HMAC failed!') // Stop admin request
    }
    else {
        // Set global variable
        KEK.value = decrypted
    }
}

const decryptAndMacApplicationKeysList = (res) => {

    // Decrypt encrypted applicationkeys list retrieved from vault
    let decipher = crypto.createDecipheriv('aes-256-cbc', KEK1.value, Buffer.from(KEK1.iv, 'hex'))
    let decrypted = decipher.update(applicationkeysEncKEK1, 'hex', 'utf-8')
    decrypted += decipher.final('utf-8')
    
    // Create hmac of decrypted applicationkeys list
    let hmac = crypto.createHmac('sha256', KEK2.value.toString('hex'))
    hmac.update(decrypted)

    if (hmac.digest('hex') != applicationkeysMacKEK2) {
        res.status(401).send('[-] Application keys list HMAC failed.')
    }
    else {
        // Set global variable
        applicationkeys = JSON.parse(decrypted)
    }
}

const encryptAndMacKeyEncryptionKey = () => {

    // Encrypt KEK.value only
    let cipher = crypto.createCipheriv('aes-256-cbc', MK1.value, Buffer.from(MK1.iv, 'hex'))
    let encrypted = cipher.update(KEK.value, 'hex', 'hex')
    encrypted += cipher.final('hex')

    // Create hmac of KEK.value
    let hmac = crypto.createHmac('sha256', MK2.value)
    hmac.update(KEK.value)

    // Set global SSM variable (both as hex)
    KEKEncMK1 = encrypted
    KEKMacMK2 = hmac.digest('hex')
}

const encryptAndMacApplicationKeysList = () => {

    // Convert applicationkeys list to one long string
    applicationkeys = JSON.stringify(applicationkeys)
    console.log("[+] Encrypting the below applicationkeys list: \n" + colors.blue(applicationkeys))

    // Encrypt the long string as hex
    let cipher = crypto.createCipheriv('aes-256-cbc', KEK1.value, Buffer.from(KEK1.iv, 'hex'))
    let encrypted = cipher.update(applicationkeys, 'utf-8', 'hex')
    encrypted += cipher.final('hex')
    console.log("[+] Encrypted applicationkeys list: \n" + colors.blue(encrypted))

    // Create hmac of applicationkeys list
    let hmac = crypto.createHmac('sha256', KEK2.value.toString('hex'))
    hmac.update(applicationkeys)

    // Set global SSM variables (both as hex)
    applicationkeysEncKEK1 = encrypted          
    applicationkeysMacKEK2 = hmac.digest('hex')

}

const createApplicationKey = (req, res) => {
    
    // Check that no application key exists with the same name
    if (isUniqueName(req) == false){
        res.status(400).send("[-] There already exists an application key for " + req.body.name + ".") 
        return
    } 
    else {
        // Create a new Key object
        const AK = new Key(req.body.name, req.body.algorithm, req.body.mode, req.body.padding, req.body.keysize, req.body.lifetime, req.body.autorotate)
        
        // 128, 192 or 256-bit AES
        if (req.body.algorithm == 'aes' && req.body.keysize != '64') {
            AK.value = crypto.randomBytes((parseInt(req.body.keysize)/8))   // Random application key value as a hex, key length depending on passed 'keysize'
            if (req.body.mode != 'ecb') { AK.iv = crypto.randomBytes(16) }  // Create random 16-byte IV for the application key (if mode is ECB then iv length is zero) 
            else { AK.iv = crypto.randomBytes(0)}                               
        }
        // Three-key 3DES
        else if (req.body.algorithm == 'des-ede3' && req.body.keysize == '192' && req.body.mode != 'gcm' && req.body.mode != 'ctr') {
            AK.value = crypto.randomBytes(24)                               // Random application key value as a hex, keys are 192-bit (24 bytes)
            if (req.body.mode != 'ecb') { AK.iv = crypto.randomBytes(8) }   // Create random 8-byte IV for the application key (if mode is ECB then iv length is zero) 
            else { AK.iv = crypto.randomBytes(0)}      
        }
        // Two-key 3DES
        else if (req.body.algorithm == 'des-ede' && req.body.keysize == '128' && req.body.mode != 'gcm' && req.body.mode != 'ctr') {
            AK.value = crypto.randomBytes(16)                               // Random application key value as a hex, keys are 128-bit (16 bytes)
            if (req.body.mode != 'ecb') { AK.iv = crypto.randomBytes(8) }   // Create random 8-byte IV for the application key (if mode is ECB then iv length is zero) 
            else { AK.iv = crypto.randomBytes(0)}      
        }
        // DES
        else if (req.body.algorithm == 'des' && req.body.keysize == '64' && req.body.mode != 'gcm' && req.body.mode != 'ctr') {
            AK.value = crypto.randomBytes(8)                                // Random application key value as a hex, keys are 64-bit (8 bytes)
            if (req.body.mode != 'ecb') { AK.iv = crypto.randomBytes(8) }   // Create random 8-byte IV for the application key (if mode is ECB then iv length is zero) 
            else { AK.iv = crypto.randomBytes(0)}      
        }
        // Incompatible algorithm and key sizes. Return 401 bad request and exit function
        else {
            res.status(401).send('[-] ' + req.body.algorithm.toUpperCase() + ' does not support the selected key length/mode.')
            return
        }

        applicationkeys.push(AK)
        console.log("[+] Pushed " + req.body.name + " Application Key onto applicationkeys list.")
    }
    

}

const writeVault = (res) => {
    
    encryptAndMacKeyEncryptionKey()
    encryptAndMacApplicationKeysList()
    
    // Populate vault object
    vault.KeyEncryptionKeyEncMK1 = KEKEncMK1
    vault.KeyEncryptionKeyMacMK2 = KEKMacMK2
    vault.ApplicationKeysEncKEK1 = applicationkeysEncKEK1
    vault.ApplicationKeysMacKEK2 = applicationkeysMacKEK2
    vault.saltMK1 = saltMK1
    vault.saltMK2 = saltMK2
    vault.saltKEK1 = saltKEK1
    vault.saltKEK2 = saltKEK2
    vault.ivMK1 = MK1.iv.toString('hex')    
    vault.ivKEK1 = KEK1.iv.toString('hex')

    // Write vault object to 'vault.json' on disk
    fs.writeFileSync(vaultPath, JSON.stringify(vault));
    res.send("[+] Successfully written to vault!")
} 

const rotateKeyEncryptionKey = (req, res) => {

    // Create KEK Key object. Generate random hex value and random IV
    KEK.value = crypto.randomBytes(32).toString('hex')

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltKEK1 = crypto.randomBytes(16).toString('hex')
    saltKEK2 = crypto.randomBytes(16).toString('hex')

    // Derive KEK1 and KEK2 and generate random KEK1 IV
    KEK1.value = crypto.pbkdf2Sync(KEK.value, saltKEK1, 100000, 32, 'sha512')
    KEK1.iv = crypto.randomBytes(16)

    KEK2.value = crypto.pbkdf2Sync(KEK.value, saltKEK2, 100000, 32, 'sha512')
    console.log(colors.green("[+] KEK rotated!"))
}

const changeMasterKey = (req, res) => {

    // Validate the provided first-time master key
    validateMK(req, res, 1)

    // Generate random 16-byte salts as hex for MK1 MK2 derivation
    saltMK1 = crypto.randomBytes(16).toString('hex')
    saltMK2 = crypto.randomBytes(16).toString('hex')

    // Derive MK1 and MK2 values and generate random MK1 IV
    MK1.value = crypto.pbkdf2Sync((req.body.MK_adminA_new + req.body.MK_adminB_new), saltMK1, 100000, 32, 'sha512')
    MK1.iv = crypto.randomBytes(16)

    MK2.value = crypto.pbkdf2Sync((req.body.MK_adminA_new + req.body.MK_adminB_new), saltMK2, 100000, 32, 'sha512')
    console.log(colors.green('[+] New 2-part master key OK.'))
}

const getApplicationKeyInfo = (req, res) => {
    const applicationkey = applicationkeys.find(key => key.name === req.body.name)
    if (!applicationkey) res.status(404).send('[-] Application key not found.')
    res.status(200).send(applicationkey)
}

const getApplicationKeysInfo = (req, res) => {
    if (!applicationkeys) res.status(404).send('[-] No application keys found.')
    res.status(200).send(applicationkeys)
}

const clientEncrypt = (req, res, k, k1, k2) => {

    KEK = k
    KEK1 = k1
    KEK2 = k2
    let ak = null

    // Decrypt and MAC applicationkeys list
    decryptAndMacApplicationKeysList(res)

    // Find application key in decrypted applicationkeys list
    applicationkeys.forEach((element) => {
        if (element.name == req.body.name) {
            ak = element
        }
    })

    // Return 401 bad request if application key does not exist
    if (ak == null) {
        res.status(401).send('[-] ' + req.body.name + ' application key not found.')
    }

    // Encrypt
    if (ak.algorithm == 'aes') {
        let cipher = crypto.createCipheriv(('aes-' + ak.keysize + '-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let encrypted = cipher.update(req.body.data, 'utf-8', 'hex')
        encrypted += cipher.final('hex')
        res.status(200).send('Encrypted: \n' + encrypted)
    }
    else if (ak.algorithm == 'des-ede3') {
        let cipher = crypto.createCipheriv(('des-ede3-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let encrypted = cipher.update(req.body.data, 'utf-8', 'hex')
        encrypted += cipher.final('hex')
        res.status(200).send('Encrypted: \n' + encrypted)
    }
    else if (ak.algorithm == 'des-ede') {
        let cipher = crypto.createCipheriv(('des-ede' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let encrypted = cipher.update(req.body.data, 'utf-8', 'hex')
        encrypted += cipher.final('hex')
        res.status(200).send('Encrypted: \n' + encrypted)
    }
    else if (ak.algorithm == 'des') {
        let cipher = crypto.createCipheriv(('des-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let encrypted = cipher.update(req.body.data, 'utf-8', 'hex')
        encrypted += cipher.final('hex')
        res.status(200).send('Encrypted: \n' + encrypted)
    }
}

const clientDecrypt = (req, res, k, k1, k2) => {

    
    KEK = k
    KEK1 = k1
    KEK2 = k2
    let ak = null

    // Decrypt and MAC applicationkeys list
    decryptAndMacApplicationKeysList(res)

    // Find application key in decrypted applicationkeys list
    applicationkeys.forEach((element) => {
        if (element.name == req.body.name) {
            ak = element
        }
    })

    // Return 401 bad request if application key does not exist
    if (ak == null) {
        res.status(401).send('[-] ' + req.body.name + ' application key not found.')
    }

    // Decrypt
    if (ak.algorithm == 'aes') {
        let decipher = crypto.createDecipheriv(('aes-' + ak.keysize + '-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let decrypted = decipher.update(req.body.data, 'hex', 'utf-8')
        decrypted += decipher.final('utf-8')
        res.status(200).send('Decrypted: \n' + decrypted)
    }
    else if (ak.algorithm == 'des-ede3') {
        let decipher = crypto.createDecipheriv(('des-ede3-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let decrypted = decipher.update(req.body.data, 'hex', 'utf-8')
        decrypted += decipher.final('utf-8')
        res.status(200).send('Decrypted: \n' + decrypted)
    }
    else if (ak.algorithm == 'des-ede') {
        let decipher = crypto.createDecipheriv(('des-ede' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let decrypted = decipher.update(req.body.data, 'hex', 'utf-8')
        decrypted += decipher.final('utf-8')
        res.status(200).send('Decrypted: \n' + decrypted)
    }
    else if (ak.algorithm == 'des') {
        let decipher = crypto.createDecipheriv(('des-' + ak.mode), Buffer.from(ak.value, 'hex'), Buffer.from(ak.iv, 'hex'))
        let decrypted = decipher.update(req.body.data, 'hex', 'utf-8')
        decrypted += decipher.final('utf-8')
        res.status(200).send('Decrypted: \n' + decrypted)
    }

}

const isCompatibleConfig = (req, res, ak) => {

    // Mode changes from ECB to other modes are not supported
    if (ak.mode == 'ecb' && req.body.mode != 'ecb') {
        return res.status(401).send('[+] Changing from ECB to non-ECB mode requires IV modifications. Create a new key with the desired mode instead.')
    }
    if (ak.algorithm != 'aes' && (req.body.mode == 'gcm' || req.body.mode == 'ctr')) {
        return res.status(401).send('[-] Galois counter mode and Counter mode are only supported by AES.')
    }
    return true
}

const updateApplicationKey = (req, res) => {
    const applicationkey = applicationkeys.find(key => key.name === req.body.name)
    if (!applicationkey) res.status(404).send('[-] Application key not found.')
    
    if (isCompatibleConfig(req, res, applicationkey) == true) {
        applicationkey.name = req.body.newname
        applicationkey.autorotate = req.body.autorotate
        applicationkey.lifetime = req.body.lifetime
        
        res.status(200).send(applicationkey)
    }
}




// TODO
// Logger/timer middleware for encrypt/decrypt
// GCM mode wherever possible
// Encrypt + Decrypt single page (2 in 1)

export {vaultExists, createApplicationKey, writeVault, rotateKeyEncryptionKey, changeMasterKey, getApplicationKeyInfo, getApplicationKeysInfo, clientEncrypt, clientDecrypt, updateApplicationKey}