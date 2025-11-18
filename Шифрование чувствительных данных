# praktika
// Использование Web Crypto API для AES шифрования
class DataEncryptor {
    async generateKey() {
        return await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async encryptData(data, key) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            dataBuffer
        );

        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    }

    async decryptData(encryptedData, key) {
        const iv = new Uint8Array(encryptedData.iv);
        const data = new Uint8Array(encryptedData.data);
        
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            data
        );

        return new TextDecoder().decode(decrypted);
    }
}
class PasswordHasher {
    async hashPassword(password, salt) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password + salt);
        
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
                   .map(b => b.toString(16).padStart(2, '0'))
                   .join('');
    }

    async verifyPassword(password, salt, hash) {
        const newHash = await this.hashPassword(password, salt);
        return newHash === hash;
    }

    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(16))
                    .reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    }
}
class AsymmetricEncryption {
    async generateKeyPair() {
        return await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async encryptWithPublicKey(data, publicKey) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        return await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            dataBuffer
        );
    }

    async decryptWithPrivateKey(encryptedData, privateKey) {
        const decrypted = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedData
        );
        
        return new TextDecoder().decode(decrypted);
    }
}
class SIPDataProtector {
    constructor() {
        this.encryptor = new DataEncryptor();
        this.hasher = new PasswordHasher();
        this.storageKey = 'sip_encryption_key';
    }

    async init() {
        let key = await this.getStoredKey();
        if (!key) {
            key = await this.encryptor.generateKey();
            await this.storeKey(key);
        }
        this.encryptionKey = key;
    }

    async getStoredKey() {
        // В реальном приложении используйте безопасное хранилище
        const stored = localStorage.getItem(this.storageKey);
        if (!stored) return null;
        
        // Здесь должна быть логика импорта ключа
        return null;
    }

    async storeKey(key) {
        // В реальном приложении используйте безопасное хранилище
        const exported = await crypto.subtle.exportKey("jwk", key);
        localStorage.setItem(this.storageKey, JSON.stringify(exported));
    }

    async protectSIPCredentials(server, username, password) {
        const salt = this.hasher.generateSalt();
        
        const protectedData = {
            server: await this.encryptor.encryptData(server, this.encryptionKey),
            username: await this.encryptor.encryptData(username, this.encryptionKey),
            password: await this.encryptor.encryptData(password, this.encryptionKey),
            salt: salt,
            passwordHash: await this.hasher.hashPassword(password, salt)
        };

        return protectedData;
    }

    async decryptSIPCredentials(encryptedData) {
        return {
            server: await this.encryptor.decryptData(encryptedData.server, this.encryptionKey),
            username: await this.encryptor.decryptData(encryptedData.username, this.encryptionKey),
            password: await this.encryptor.decryptData(encryptedData.password, this.encryptionKey)
        };
    }

    // Очистка чувствительных данных из памяти
    clearSensitiveData() {
        this.encryptionKey = null;
        // Принудительный сборщик мусора (где поддерживается)
        if (global.gc) global.gc();
    }
}
// Защита от атак перехвата
class SecurityManager {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/[<>]/g, '')
            .trim()
            .substring(0, 255); // Ограничение длины
    }

    static validateSIPData(data) {
        const patterns = {
            server: /^[a-zA-Z0-9.-]+$/,
            username: /^[a-zA-Z0-9@._-]+$/,
            password: /^[!-~]+$/ // Печатные ASCII символы
        };

        return Object.keys(patterns).every(key => 
            patterns[key].test(data[key])
        );
    }

    // Таймаут для защиты от brute-force
    static async withTimeout(promise, timeout = 5000) {
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Timeout')), timeout)
        );
        
        return Promise.race([promise, timeoutPromise]);
    }
}
class SecureSIPClient {
    constructor() {
        this.protector = new SIPDataProtector();
        this.isInitialized = false;
    }

    async initialize() {
        await this.protector.init();
        this.isInitialized = true;
    }

    async connect(server, username, password) {
        if (!this.isInitialized) {
            throw new Error('Security module not initialized');
        }

        // Валидация входных данных
        const sanitizedData = {
            server: SecurityManager.sanitizeInput(server),
            username: SecurityManager.sanitizeInput(username),
            password: SecurityManager.sanitizeInput(password)
        };

        if (!SecurityManager.validateSIPData(sanitizedData)) {
            throw new Error('Invalid input data');
        }

        try {
            // Шифрование учетных данных
            const encrypted = await SecurityManager.withTimeout(
                this.protector.protectSIPCredentials(
                    sanitizedData.server,
                    sanitizedData.username,
                    sanitizedData.password
                )
            );

            // Здесь будет реальное SIP-подключение
            await this.performSIPConnection(encrypted);
            
        } catch (error) {
            this.protector.clearSensitiveData();
            throw error;
        }
    }

    async disconnect() {
        this.protector.clearSensitiveData();
        // Дополнительная очистка
        Object.keys(this).forEach(key => {
            if (this[key] && typeof this[key].clear === 'function') {
                this[key].clear();
            }
        });
    }
}
