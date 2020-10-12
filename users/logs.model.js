const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const logsSchema = new Schema({
    userid: { type: String, required: true },
    isLogin: { type: Boolean, required: true },
    ip: { type: String, required: true }
}, { timestamps: true });

logsSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('logs', logsSchema);