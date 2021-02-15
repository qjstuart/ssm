// 'classes' for key (there are no classes in JS): Instead we use constructor functions. 
// Key TYPE: AES, DES, 3DES etc.
// Key VALUE: secretttttt
// Key EXPRIY DATE

// Constructor function
export default function Key(name, algorithm, mode, padding, keysize, lifetime, autorotate) {

    this.name = name
    this.algorithm = algorithm
    this.mode = mode
    this.padding = padding
    this.keysize = keysize
    this.iv = null
    this.lifetime = lifetime
    this.autorotate = autorotate
    this.encryptedvalue = null
    
    // Name getters and setters
    Object.defineProperty(this, 'getname', {
        get: function() {
            return name
        },
        set: function(value) {
            name = value
        }
    })
}





// key getter must check for key expiry. if expired, generate a new version