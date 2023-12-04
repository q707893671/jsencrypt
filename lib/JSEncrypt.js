var _a;
import { b64tohex, hex2b64 } from "./lib/jsbn/base64";
import { JSEncryptRSAKey } from "./JSEncryptRSAKey";
var version = typeof process !== 'undefined'
    ? (_a = process.env) === null || _a === void 0 ? void 0 : _a.npm_package_version
    : undefined;
/**
 *
 * @param {Object} [options = {}] - An object to customize JSEncrypt behaviour
 * possible parameters are:
 * - default_key_size        {number}  default: 1024 the key size in bit
 * - default_public_exponent {string}  default: '010001' the hexadecimal representation of the public exponent
 * - log                     {boolean} default: false whether log warn/error or not
 * @constructor
 */
var JSEncrypt = /** @class */ (function () {
    function JSEncrypt(options) {
        if (options === void 0) { options = {}; }
        options = options || {};
        this.default_key_size = options.default_key_size
            ? parseInt(options.default_key_size, 10)
            : 1024;
        this.default_public_exponent = options.default_public_exponent || "010001"; // 65537 default openssl public exponent for rsa key type
        this.log = options.log || false;
        // The private and public key.
        this.key = null;
    }
    /**
     * Method to set the rsa key parameter (one method is enough to set both the public
     * and the private key, since the private key contains the public key paramenters)
     * Log a warning if logs are enabled
     * @param {Object|string} key the pem encoded string or an object (with or without header/footer)
     * @public
     */
    JSEncrypt.prototype.setKey = function (key) {
        if (this.log && this.key) {
            console.warn("A key was already set, overriding existing.");
        }
        this.key = new JSEncryptRSAKey(key);
    };
    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    JSEncrypt.prototype.setPrivateKey = function (privkey) {
        // Create the key.
        this.setKey(privkey);
    };
    /**
     * Proxy method for setKey, for api compatibility
     * @see setKey
     * @public
     */
    JSEncrypt.prototype.setPublicKey = function (pubkey) {
        // Sets the public key.
        this.setKey(pubkey);
    };
    /**
     * Proxy method for RSAKey object's decrypt, decrypt the string using the private
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str base64 encoded crypted string to decrypt
     * @return {string} the decrypted string
     * @public
     */
    JSEncrypt.prototype.decrypt = function (str) {
        // Return the decrypted string.
        try {
            return this.getKey().decrypt(b64tohex(str));
        }
        catch (ex) {
            return false;
        }
    };
    /**
     * Proxy method for RSAKey object's encrypt, encrypt the string using the public
     * components of the rsa key object. Note that if the object was not set will be created
     * on the fly (by the getKey method) using the parameters passed in the JSEncrypt constructor
     * @param {string} str the string to encrypt
     * @return {string} the encrypted string encoded in base64
     * @public
     */
    JSEncrypt.prototype.encrypt = function (str) {
        // Return the encrypted string.
        try {
            return hex2b64(this.getKey().encrypt(str));
        }
        catch (ex) {
            return false;
        }
    };
    /**
     * Proxy method for RSAKey object's sign.
     * @param {string} str the string to sign
     * @param {function} digestMethod hash method
     * @param {string} digestName the name of the hash algorithm
     * @return {string} the signature encoded in base64
     * @public
     */
    JSEncrypt.prototype.sign = function (str, digestMethod, digestName) {
        // return the RSA signature of 'str' in 'hex' format.
        try {
            return hex2b64(this.getKey().sign(str, digestMethod, digestName));
        }
        catch (ex) {
            return false;
        }
    };
    /**
     * Proxy method for RSAKey object's verify.
     * @param {string} str the string to verify
     * @param {string} signature the signature encoded in base64 to compare the string to
     * @param {function} digestMethod hash method
     * @return {boolean} whether the data and signature match
     * @public
     */
    JSEncrypt.prototype.verify = function (str, signature, digestMethod) {
        // Return the decrypted 'digest' of the signature.
        try {
            return this.getKey().verify(str, b64tohex(signature), digestMethod);
        }
        catch (ex) {
            return false;
        }
    };
    /**
     * Getter for the current JSEncryptRSAKey object. If it doesn't exists a new object
     * will be created and returned
     * @param {callback} [cb] the callback to be called if we want the key to be generated
     * in an async fashion
     * @returns {JSEncryptRSAKey} the JSEncryptRSAKey object
     * @public
     */
    JSEncrypt.prototype.getKey = function (cb) {
        // Only create new if it does not exist.
        if (!this.key) {
            // Get a new private key.
            this.key = new JSEncryptRSAKey();
            if (cb && {}.toString.call(cb) === "[object Function]") {
                this.key.generateAsync(this.default_key_size, this.default_public_exponent, cb);
                return;
            }
            // Generate the key.
            this.key.generate(this.default_key_size, this.default_public_exponent);
        }
        return this.key;
    };
    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITH header and footer
     * @public
     */
    JSEncrypt.prototype.getPrivateKey = function () {
        // Return the private representation of this key.
        return this.getKey().getPrivateKey();
    };
    /**
     * Returns the pem encoded representation of the private key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the private key WITHOUT header and footer
     * @public
     */
    JSEncrypt.prototype.getPrivateKeyB64 = function () {
        // Return the private representation of this key.
        return this.getKey().getPrivateBaseKeyB64();
    };
    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITH header and footer
     * @public
     */
    JSEncrypt.prototype.getPublicKey = function () {
        // Return the private representation of this key.
        return this.getKey().getPublicKey();
    };
    /**
     * Returns the pem encoded representation of the public key
     * If the key doesn't exists a new key will be created
     * @returns {string} pem encoded representation of the public key WITHOUT header and footer
     * @public
     */
    JSEncrypt.prototype.getPublicKeyB64 = function () {
        // Return the private representation of this key.
        return this.getKey().getPublicBaseKeyB64();
    };
    	//任意长度RSA Key分段加密解密长字符串
	
	//获取RSA key 长度
	JSEncrypt.prototype.getkeylength = function () {
        return ((this.key.n.bitLength()+7)>>3);
     };
     
     // 分段解密，支持中文
     JSEncrypt.prototype.decryptUnicodeLong = function (string) {
        var k = this.getKey();
        //解密长度=key size.hex2b64结果是每字节每两字符，所以直接*2
        var maxLength = ((k.n.bitLength()+7)>>3)*2;
        try {
            var hexString = b64tohex(string);
            var decryptedString = "";
            var rexStr=".{1," + maxLength  + "}";
            var rex =new RegExp(rexStr, 'g'); 
            var subStrArray = hexString.match(rex);
            if(subStrArray){
                subStrArray.forEach(function (entry) {
                    decryptedString += k.decrypt(entry);
                });
                return decryptedString;
            }
        } catch (ex) {
            return false;
        }
    };
        
    // 分段加密，支持中文
    JSEncrypt.prototype.encryptUnicodeLong = function (string) {
        var k = this.getKey();
        //根据key所能编码的最大长度来定分段长度。key size - 11：11字节随机padding使每次加密结果都不同。
        var maxLength = ((k.n.bitLength()+7)>>3)-11;
        try {
            var subStr="", encryptedString = "";
            var subStart = 0, subEnd=0;
            var bitLen=0, tmpPoint=0;
            for(var i = 0, len = string.length; i < len; i++){
                //js 是使用 Unicode 编码的，每个字符所占用的字节数不同
                var charCode = string.charCodeAt(i);
                if(charCode <= 0x007f) {
                    bitLen += 1;
                }else if(charCode <= 0x07ff){
                    bitLen += 2;
                }else if(charCode <= 0xffff){
                    bitLen += 3;
                }else{
                    bitLen += 4;
                }
                //字节数到达上限，获取子字符串加密并追加到总字符串后。更新下一个字符串起始位置及字节计算。
                if(bitLen>maxLength){
                    subStr=string.substring(subStart,subEnd)
                    encryptedString += k.encrypt(subStr);
                    subStart=subEnd;
                    bitLen=bitLen-tmpPoint;
                }else{
                    subEnd=i;
                    tmpPoint=bitLen;
                }
            }
            subStr=string.substring(subStart,len)
            encryptedString += k.encrypt(subStr);
            return hex2b64(encryptedString);
        } catch (ex) {
            return false;
        }
    };
    //添加的函数与方法结束
 
    JSEncrypt.version = version;
    return JSEncrypt;
}());
export { JSEncrypt };
