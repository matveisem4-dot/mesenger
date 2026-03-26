const fs = require('fs');
const path = 'C:\\MessengerData\\logs.txt';

function saveMessage(msg) {
    const encryptedMsg = encrypt(msg); // Шифруем перед записью
    fs.appendFileSync(path, encryptedMsg + '\n');
}
