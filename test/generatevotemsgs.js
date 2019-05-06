const fs = require("fs");
const ethUtil = require("ethereumjs-util");

const addresses = require("./testaddresses.json");
const count = 10


let signatures = [];
for (let i=0; i<count; i++) {
    const privateKey = addresses[i].privKey;
    var privateKeyBuffer = new Buffer(privateKey, 'hex')

    //const pollId = 0;
    //const optionVoted = 1;
    const msg = Buffer.from("000001", "hex");

    //const msg = Buffer.from("30", "hex");
    const msgHash = ethUtil.hashPersonalMessage(msg);
    const sig = ethUtil.ecsign(msgHash, privateKeyBuffer);

    signatures.push(sig);
}

console.log("===== VOTES =====");
for (let i=0; i<count; i++) {
    process.stdout.write("1,");
}
console.log("");

console.log("===== R =====");
for (let i=0; i<count; i++) {
    process.stdout.write(`0x${signatures[i].r.toString('hex')},`);
}
console.log("");

console.log("===== S =====");
for (let i=0; i<count; i++) {
    process.stdout.write(`0x${signatures[i].s.toString('hex')},`);
}
console.log("");

console.log("===== V =====");
for (let i=0; i<count; i++) {
    process.stdout.write(`${signatures[i].v},`);
}
console.log("");
