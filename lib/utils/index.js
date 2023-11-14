"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decompactSignature = exports.compactSignature = exports.multibaseDecode = exports.convertMultiBase = exports.w3cDate = void 0;
const js_crypto_1 = require("@iden3/js-crypto");
const multibase_1 = __importDefault(require("multibase"));
function w3cDate(date) {
    let result = new Date();
    if (typeof date === "number" || typeof date === "string") {
        result = new Date(date);
    }
    const str = result.toISOString();
    return str.substr(0, str.length - 5) + "Z";
}
exports.w3cDate = w3cDate;
function convertMultiBase(data) {
    return Buffer.from(multibase_1.default.encode("base58btc", data)).toString();
}
exports.convertMultiBase = convertMultiBase;
function multibaseDecode(signature) {
    return multibase_1.default.decode(signature);
}
exports.multibaseDecode = multibaseDecode;
function compactSignature(signature) {
    return signature.compress();
}
exports.compactSignature = compactSignature;
function decompactSignature(sign) {
    const decoded = multibaseDecode(sign);
    const signature = js_crypto_1.Signature.newFromCompressed(decoded);
    return signature;
}
exports.decompactSignature = decompactSignature;
//# sourceMappingURL=index.js.map