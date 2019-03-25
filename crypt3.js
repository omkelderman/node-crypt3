const cryptbindings = require('./build/Release/cryptbindings');
const crypto = require('crypto');

function genShaRoundsString(rounds) {
    if(!rounds) return '';

    return `rounds=${rounds}$`;
}


const salters = {
    md5:    {
        saltBytes: 6,
        builder: (_, saltStr) => '$1$' + saltStr,
    },
    bcrypt: {
        saltBytes: 16,
        strLenCap: 22,
        builder: (rounds, saltStr) => '$2b$' + (rounds ? rounds : 10) + '$' + saltStr,
    },
    sha256: {
        saltBytes: 12,
        builder: (rounds, saltStr) => '$5$' + genShaRoundsString(rounds) + saltStr,
    },
    sha512: {
        saltBytes: 12,
        builder: (rounds, saltStr) => '$6$' + genShaRoundsString(rounds) + saltStr,
    }
};

function genSaltSync(type, rounds) {
    type = type || 'sha512';
    let salter = salters[type];
    if(!salter) throw new TypeError('Unknown salt type: ' + type);
    
    let saltStr = crypto.randomBytes(salter.saltBytes).toString('base64');
    if(salter.strLenCap) {
        saltStr = saltStr.substr(0, salter.strLenCap);
    }
    return salter.builder(rounds, saltStr);
}

function genSalt(type, rounds, cb) {
    // create cb if not there and return promise
    if(!cb) {
        return new Promise((resolve, reject) => {
            genSalt(type, rounds, (err, result) => {
                if(err) return reject(err);
                resolve(result);
            });
        });
    }

    type = type || 'sha512';
    let salter = salters[type];
    if(!salter)  return cb(new TypeError('Unknown salt type: ' + type));

    crypto.randomBytes(salter.saltBytes, (err, result) => {
        if(err) return cb(err);

        let saltStr = result.toString('base64');
        if(salter.strLenCap) {
            saltStr = saltStr.substr(0, salter.strLenCap);
        }
        cb(null, salter.builder(rounds, saltStr));
    });
}

function hashSync(data, type, rounds) {
    let salt = genSaltSync(type, rounds);
    return cryptbindings.cryptSync(data, salt);
}

function hashSyncManualSalt(data, salt) {
    return cryptbindings.cryptSync(data, salt);
}

function verifySync(data, hash) {
    var result = cryptbindings.cryptSync(data, hash);
    return result == hash;
}

function hash(data, type, rounds, cb) {
    // create cb if not there and return promise
    if(!cb) {
        return new Promise((resolve, reject) => {
            hash(data, type, rounds, (err, result) => {
                if(err) return reject(err);
                resolve(result);
            });
        });
    }

    genSalt(type, rounds, (err, salt) => {
        if(err) return cb(err);

        cryptbindings.cryptAsync(data, salt, (err, result) => {
            if(err) return cb(err);

            cb(null, result);
        });
    });
}

function hashManualSalt(data, salt, cb) {
    if(!cb) {
        return new Promise((resolve, reject) => {
            hashManualSalt(data, salt, (err, result) => {
                if(err) return reject(err);
                resolve(result);
            });
        });
    }

    cryptbindings.cryptAsync(data, salt, (err, result) => {
        if(err) return cb(err);

        cb(null, result);
    });
}

function verify(data, hash, cb) {
    if(!cb) {
        return new Promise((resolve, reject) => {
            verify(data, hash, (err, result) => {
                if(err) return reject(err);
                resolve(result);
            });
        });
    }

    cryptbindings.cryptAsync(data, hash, (err, result) => {
        if(err) return cb(err);

        cb(null, result == hash);
    });
}

// sync
module.exports.genSaltSync = genSaltSync;
module.exports.hashSync = hashSync;
module.exports.hashSyncManualSalt = hashSyncManualSalt;
module.exports.verifySync = verifySync;

// async
module.exports.genSalt = genSalt;
module.exports.hash = hash;
module.exports.hashManualSalt = hashManualSalt;
module.exports.verify = verify;
