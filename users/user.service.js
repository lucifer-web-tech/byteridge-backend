const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;
const Log = db.Log;

module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    logOut,
    audit,
    delete: _delete
};

async function authenticate({ username, password, isAuditor, ip }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        const newLog = new Log({ userid: user._id, isLogin: true, ip: ip });
        const logid = await newLog.save();
        return {
            ...userWithoutHash,
            token,
            logid: logid._id
        };
    }
}

async function logOut({ logid }) {
    return await Log.findByIdAndUpdate(logid, { isLogin: false });
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function audit(pagenum) {
    const query = [{
        "$facet": {
            "users": [
                { $skip: (pagenum - 1) * 5 }, { $limit: 5 }, {
                    $addFields: {
                        identifier: { $toString: "$_id" }
                    }
                }, {
                    $lookup: {
                        from: 'logs',
                        localField: 'identifier',
                        foreignField: 'userid',
                        as: 'logs'
                    }
                }, {
                    $project: {
                        username: 1,
                        lastName: 1,
                        firstName: 1,
                        username: 1,
                        role: 1,
                        lastlog: { $arrayElemAt: ["$logs", -1] }
                    }
                }
            ],
            "count": [
                { "$count": "count" }
            ]
        }
    }];

    return await User.aggregate(query);
}
