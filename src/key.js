// Constructor function
export function Key(name, algorithm, mode, padding, keysize, lifetime, autorotate) {

    this.name = name
    this.algorithm = algorithm
    this.mode = mode
    this.padding = padding
    this.keysize = keysize
    this.iv = null
    this.lifetime = lifetime
    this.autorotate = autorotate
    this.value = null
}