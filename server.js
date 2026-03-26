const axios = require('axios');
const fs = require('fs');

const REPO = "ТВОЙ_НИК/РЕПО";
const TOKEN = process.env.GH_TOKEN;

async function manageDatabase() {
    console.log("Checking GitHub Database...");
    
    // Получаем все сообщения
    const res = await axios.get(`https://api.github.com/repos/${REPO}/issues/1/comments`, {
        headers: { Authorization: `token ${TOKEN}` }
    });

    const messages = res.data;

    // Если сообщений больше 500, переносим их на диск C и удаляем из GitHub
    if (messages.length > 500) {
        console.log("Archiving old messages to C:/Data...");
        const archivePath = 'C:\\Data\\archive_' + Date.now() + '.json';
        if (!fs.existsSync('C:\\Data')) fs.mkdirSync('C:\\Data');
        
        fs.writeFileSync(archivePath, JSON.stringify(messages));
        
        // Удаление старых комментариев через API
        for (let i = 0; i < 100; i++) {
            await axios.delete(`https://api.github.com/repos/${REPO}/issues/comments/${messages[i].id}`, {
                headers: { Authorization: `token ${TOKEN}` }
            });
        }
    }
}

manageDatabase();
