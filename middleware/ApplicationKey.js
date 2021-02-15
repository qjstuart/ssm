import JsonFind from 'json-find';
import { loadVault } from './vault.js';

export default class ApplicationKey {
    constructor(name, algorithm, algorithmParams, iv, keyLifetime, autoRotate, versions) {
        this.name = name;
        this.algorithm = algorithm;
        this.algorithmParams = algorithmParams;
        this.iv = iv;
        this.keyLifetime = keyLifetime;
        this.autoRotate = autoRotate;
        this.versions = versions;
    }


    create(req, res) { 
        let vault = loadVault();
        const finder = JsonFind(vault);
    
        // if there is an applicationKeys entry in vault file
        if (!finder.checkKey('applicationKeys') == false) { 
            // match supplied name with any existing names
            for (const name in vault.applicationKeys) {
                if (name == req.body.name) {
                    res.status(409).send("[-] There already exists an application key with the name provided.");
                }
            }

            // new AK object
            let AK = new ApplicationKey();
            AK.name = req.body.name;
            AK.algorithm = req.body.algorithm;
            AK.algorithmParams = req.body.algorithmParams;
            AK.keyLifetime = req.body.keyLifetime;
            AK.autoRotate = req.body.autoRotate;




        }
    }

    generateKeyValue(algorithm, algorithmParams) {
        switch (algorithm) {
            case 'DES':
                // TODO DES logic
                break;
            case '3DES':
                // 3DES logic
                break;
            case 'AES':
                // AES logic
        }
    }
}







