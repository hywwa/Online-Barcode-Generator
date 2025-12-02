// 导入依赖模块
const express = require('express');
const cors = require('cors');
const bwipjs = require('bwip-js');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
// 使用pngjs库处理PNG图像，实现像素级操作
const { PNG } = require('pngjs');

// 初始化Express应用
const app = express();
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';


// 使用标准的JSON请求体解析中间件
app.use(express.json());

// 默认条码配置 - 用于初始化每个用户的配置
const DEFAULT_BARCODE_CONFIG = {
    singleBarcodeWidthMm: 50, // 单个条码宽度(mm)
    spacingMm: 7.5,           // 条码之间的间隙(mm)
    sideMarginMm: 8           // 图片两边间距(mm)
};

// 应用配置
const APP_CONFIG = {
    // 密码配置（建议在生产环境使用环境变量）

    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'keda666', // 生成验证码的管理员密码
    
    // 静态文件配置
    STATIC_FILES: {
        MAX_AGE: '1d',
        PUBLIC_PATH: path.join(__dirname, 'public')
    }
};

// 从配置中解构常量，便于使用
const { ADMIN_PASSWORD } = APP_CONFIG;

// 日志级别常量
const LOG_LEVELS = {
    DEBUG: 'debug',
    INFO: 'info',
    WARN: 'warn',
    ERROR: 'error',
    SECURITY: 'security'
};

// 日志记录函数 - 增强版本，保留完整错误信息
function log(level, message, metadata = {}) {
    // 只记录关键日志：错误、安全和基本的用户验证/管理员登录信息
    if (level === LOG_LEVELS.ERROR || 
        level === LOG_LEVELS.SECURITY ||
        (level === LOG_LEVELS.INFO && 
         (message.includes('管理员登录') || 
          message.includes('验证码验证') || 
          message.includes('用户验证')))) {
        const timestamp = new Date().toISOString();
        
        // 基础日志条目
        const logEntry = {
            timestamp,
            message
        };
        
        // 为错误日志添加完整信息
        if (level === LOG_LEVELS.ERROR) {
            // 添加所有错误相关信息
            if (metadata.error) logEntry.error = metadata.error;
            if (metadata.stack) logEntry.stack = metadata.stack;
            if (metadata.path) logEntry.path = metadata.path;
            if (metadata.method) logEntry.method = metadata.method;
            if (metadata.ip) logEntry.ip = metadata.ip;
        } else {
            // 非错误日志保留简化格式
            if (metadata.ip) logEntry.ip = metadata.ip;
        }
        
        // 根据日志级别使用不同的console方法
        switch(level) {
            case LOG_LEVELS.ERROR:
                console.error('[ERROR]', JSON.stringify(logEntry));
                break;
            case LOG_LEVELS.SECURITY:
                console.warn('[SECURITY]', JSON.stringify(logEntry));
                break;
            case LOG_LEVELS.INFO:
                console.info('[INFO]', JSON.stringify(logEntry));
                break;
        }
    }
}

// 验证码系统配置
const VERIFICATION_CONFIG = {
    CODE_LENGTH: 4,                  // 验证码长度
    MAX_ATTEMPTS: 5,                 // 每个验证码最大尝试次数
    DEFAULT_EXPIRY_HOURS: 24,        // 默认有效期（小时）
    MAX_EXPIRY_HOURS: 168,           // 最大有效期（7天）
    RATE_LIMIT_WINDOW_MS: 5 * 60 * 1000,   // 速率限制窗口（5分钟）
    MAX_REQUESTS_PER_WINDOW: 10,     // 每个窗口最大请求数
    LOCKOUT_MINUTES: 15,             // 多次失败后的锁定时间
    CLEANUP_INTERVAL_MS: 15 * 60 * 1000 // 清理间隔（15分钟）
};

// 简化的日志记录辅助函数
function logUserAuth(message, ip) {
    console.log(`[AUTH] ${new Date().toISOString()} - ${message} - IP: ${ip}`);
}

function logAdminLogin(success, message, ip) {
    console.log(`[ADMIN] ${new Date().toISOString()} - ${success ? 'SUCCESS' : 'FAILED'} - ${message} - IP: ${ip}`);
}

// 验证码存储结构
class VerificationCodeStore {
    constructor() {
        // 确定数据文件夹路径：如果在dist文件夹中运行，则数据文件夹位于dist同级目录；否则位于当前目录
        const isRunningInDist = __dirname.endsWith('dist');
        const dataDir = isRunningInDist ? path.join(__dirname, '..', 'data') : path.join(__dirname, 'data');
        this._storagePath = path.join(dataDir, 'verification_codes.json');
        this._storage = this._loadFromFile();
    }
    
    // 从文件加载数据
    _loadFromFile() {
        try {
            // 确保数据目录存在
            if (!fs.existsSync(path.dirname(this._storagePath))) {
                fs.mkdirSync(path.dirname(this._storagePath), { recursive: true });
            }
            
            // 如果文件不存在，返回空对象
            if (!fs.existsSync(this._storagePath)) {
                return {};
            }
            
            // 读取并解析文件
            const data = fs.readFileSync(this._storagePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Failed to load verification codes from file:', error);
            return {};
        }
    }
    
    // 保存数据到文件
    _saveToFile() {
        try {
            // 确保数据目录存在
            if (!fs.existsSync(path.dirname(this._storagePath))) {
                fs.mkdirSync(path.dirname(this._storagePath), { recursive: true });
            }
            
            // 写入文件
            fs.writeFileSync(this._storagePath, JSON.stringify(this._storage, null, 2), 'utf8');
            return true;
        } catch (error) {
            console.error('Failed to save verification codes to file:', error);
            return false;
        }
    }
    
    // 添加验证码
    add(code, info) {
        this._storage[code] = {
            ...info,
            metadata: {
                createdTimestamp: Date.now(),
                lastAccessed: Date.now(),
                accessCount: 0
            }
        };
        this._saveToFile();
        return true;
    }
    
    // 获取验证码信息
    get(code) {
        const info = this._storage[code];
        if (info) {
            // 更新访问信息
            info.metadata.lastAccessed = Date.now();
            info.metadata.accessCount++;
            this._saveToFile();
        }
        return info;
    }
    
    // 更新验证码
    update(code, updates) {
        if (this._storage[code]) {
            this._storage[code] = {
                ...this._storage[code],
                ...updates,
                metadata: {
                    ...this._storage[code].metadata,
                    lastAccessed: Date.now()
                }
            };
            this._saveToFile();
            return true;
        }
        return false;
    }
    
    // 删除验证码
    delete(code) {
        if (this._storage[code]) {
            delete this._storage[code];
            this._saveToFile();
            return true;
        }
        return false;
    }
    
    // 清理过期验证码
    cleanupExpired() {
        const now = Date.now();
        let deletedCount = 0;
        
        for (const [code, info] of Object.entries(this._storage)) {
            if (now > new Date(info.expiry).getTime()) {
                delete this._storage[code];
                deletedCount++;
            }
        }
        
        if (deletedCount > 0) {
            this._saveToFile();
        }
        
        return deletedCount;
    }
    
    // 获取所有验证码（仅管理员使用）
    getAll() {
        return this._storage;
    }
    
    // 获取统计信息
    getStats() {
        const now = Date.now();
        let total = 0;
        let activeCodes = 0;
        let used = 0;
        let expired = 0;
        
        for (const info of Object.values(this._storage)) {
            total++;
            if (info.used) used++;
            if (now > new Date(info.expiry).getTime()) expired++;
            if (!info.used && now <= new Date(info.expiry).getTime()) activeCodes++;
        }
        
        return { total, activeCodes, used, expired };
    }
}

// 创建验证码存储实例
const verificationCodes = new VerificationCodeStore();

// 会话存储结构
class SessionStore {
    constructor() {
        // 确定数据文件夹路径：如果在dist文件夹中运行，则数据文件夹位于dist同级目录；否则位于当前目录
        const isRunningInDist = __dirname.endsWith('dist');
        const dataDir = isRunningInDist ? path.join(__dirname, '..', 'data') : path.join(__dirname, 'data');
        this._storagePath = path.join(dataDir, 'sessions.json');
        this._storage = this._loadFromFile();
    }
    
    // 从文件加载数据
    _loadFromFile() {
        try {
            // 确保数据目录存在
            if (!fs.existsSync(path.dirname(this._storagePath))) {
                fs.mkdirSync(path.dirname(this._storagePath), { recursive: true });
            }
            
            // 如果文件不存在，返回空对象
            if (!fs.existsSync(this._storagePath)) {
                return {};
            }
            
            // 读取并解析文件
            const data = fs.readFileSync(this._storagePath, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Failed to load sessions from file:', error);
            return {};
        }
    }
    
    // 保存数据到文件
    _saveToFile() {
        try {
            // 确保数据目录存在
            if (!fs.existsSync(path.dirname(this._storagePath))) {
                fs.mkdirSync(path.dirname(this._storagePath), { recursive: true });
            }
            
            // 写入文件
            fs.writeFileSync(this._storagePath, JSON.stringify(this._storage, null, 2), 'utf8');
            return true;
        } catch (error) {
            console.error('Failed to save sessions to file:', error);
            return false;
        }
    }
    
    // 添加会话
    add(sessionId, info) {
        this._storage[sessionId] = {
            ...info,
            metadata: {
                createdTimestamp: Date.now(),
                lastAccessed: Date.now(),
                accessCount: 1
            }
        };
        // 只有非管理员会话才写入文件
        if (!info.isAdmin) {
            this._saveToFile();
        }
        return true;
    }
    
    // 获取会话信息
    get(sessionId) {
        const info = this._storage[sessionId];
        if (info) {
            // 更新访问信息
            info.metadata.lastAccessed = Date.now();
            info.metadata.accessCount++;
            // 只有非管理员会话才写入文件
            if (!info.isAdmin) {
                this._saveToFile();
            }
        }
        return info;
    }
    
    // 更新会话
    update(sessionId, updates) {
        if (this._storage[sessionId]) {
            this._storage[sessionId] = {
                ...this._storage[sessionId],
                ...updates,
                metadata: {
                    ...this._storage[sessionId].metadata,
                    lastAccessed: Date.now()
                }
            };
            // 只有非管理员会话才写入文件
            if (!this._storage[sessionId].isAdmin) {
                this._saveToFile();
            }
            return true;
        }
        return false;
    }
    
    // 删除会话
    delete(sessionId) {
        if (this._storage[sessionId]) {
            const isAdminSession = this._storage[sessionId].isAdmin;
            delete this._storage[sessionId];
            // 只有非管理员会话才写入文件
            if (!isAdminSession) {
                this._saveToFile();
            }
            return true;
        }
        return false;
    }
    
    // 清理过期会话
    cleanupExpired(maxAgeMs) {
        const now = Date.now();
        let deletedCount = 0;
        let hasNonAdminSessionDeleted = false;
        
        for (const [sessionId, info] of Object.entries(this._storage)) {
            let isExpired = false;
            
            if (info.isAdmin) {
                // 管理员会话：使用固定的maxAgeMs（7天），但基于最后活动时间
                isExpired = now - info.metadata.lastAccessed > maxAgeMs;
            } else {
                // 用户会话：使用会话自己的expiryTime
                isExpired = now > info.expiryTime;
            }
            
            if (isExpired) {
                const isAdminSession = info.isAdmin;
                delete this._storage[sessionId];
                deletedCount++;
                
                // 只有非管理员会话才需要写入文件
                if (!isAdminSession) {
                    hasNonAdminSessionDeleted = true;
                }
            }
        }
        
        if (hasNonAdminSessionDeleted) {
            this._saveToFile();
        }
        
        return deletedCount;
    }
    
    // 获取统计信息
    getStats() {
        const now = Date.now();
        const oneHourAgo = now - 60 * 60 * 1000;
        let total = 0;
        let activeUsers = 0;
        let adminSessions = 0;
        
        for (const info of Object.values(this._storage)) {
            total++;
            if (info.isAdmin) adminSessions++;
            if (info.metadata.lastAccessed > oneHourAgo) {
                activeUsers++;
            }
        }
        
        return { total, activeUsers, adminSessions };
    }
    
    // 获取所有会话（仅管理员使用）
    getAll() {
        // 不返回管理员会话
        const nonAdminSessions = {};
        for (const [sessionId, session] of Object.entries(this._storage)) {
            if (!session.isAdmin) {
                nonAdminSessions[sessionId] = session;
            }
        }
        return nonAdminSessions;
    }
}

// 创建会话存储实例
const sessions = new SessionStore();

// 速率限制和IP锁定存储
const ipAccessRecords = {}; // IP访问记录，用于速率限制
const lockedIps = {};       // 锁定的IP记录

/**
 * 启动定期清理任务
 * 负责清理过期的验证码、会话和IP锁定记录
 */
function startCleanupTasks() {
    const ONE_WEEK_MS = 24 * 7 * 60 * 60 * 1000; // 7天
    
    // 设置定时器执行定期清理
    setInterval(() => {
        // 清理过期验证码
        const codeCleaned = verificationCodes.cleanupExpired();
        
        // 清理过期会话（7天过期）
        const sessionCleaned = sessions.cleanupExpired(ONE_WEEK_MS);
        
        // 清理过期的IP锁定记录
        const initialLockCount = Object.keys(lockedIps).length;
        Object.keys(lockedIps).forEach(ip => {
            // isIpLocked函数会自动删除过期的锁定
            isIpLocked(ip);
        });
        const lockCleaned = initialLockCount - Object.keys(lockedIps).length;
        
        // 只有当有记录被清理时才记录日志
        if (codeCleaned > 0 || sessionCleaned > 0 || lockCleaned > 0) {
            log(LOG_LEVELS.INFO, '定期清理任务完成', {
                cleanedCodes: codeCleaned,
                cleanedSessions: sessionCleaned,
                cleanedLocks: lockCleaned,
                remainingCodes: verificationCodes.getStats().total,
                remainingSessions: sessions.getStats().total,
                remainingLocks: Object.keys(lockedIps).length
            });
        }
    }, VERIFICATION_CONFIG.CLEANUP_INTERVAL_MS);
    
    log(LOG_LEVELS.INFO, '自动清理任务已启动', {
        intervalMinutes: VERIFICATION_CONFIG.CLEANUP_INTERVAL_MS / 60000
    });
}

/**
 * 生成四位数验证码
 * @returns {string} - 生成的不重复四位数验证码
 */
function generateVerificationCode() {
    let code;
    
    // 确保生成的验证码不重复
    do {
        code = Math.floor(1000 + Math.random() * 9000).toString();
    } while (verificationCodes.get(code));
    
    return code;
}

/**
 * 验证验证码是否有效
 * @param {string} code - 要验证的验证码
 * @returns {boolean} - 验证码是否有效
 */
function isValidVerificationCode(code) {
    const codeInfo = verificationCodes.get(code);
    if (!codeInfo) return false;
    
    // 检查是否已使用
    if (codeInfo.used) return false;
    
    // 检查是否过期
    if (new Date() > codeInfo.expiry) return false;
    
    // 修复常量名大小写错误
    if (codeInfo.attempts >= VERIFICATION_CONFIG.MAX_ATTEMPTS) return false;
    
    return true;
}

/**
 * 创建唯一会话ID
 * @returns {string} - 生成的不重复会话ID
 */
function createSessionId() {
    let sessionId;
    
    // 确保生成的会话ID不重复
    do {
        sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substring(2, 15);
    } while (sessions.get(sessionId));
    
    return sessionId;
}

// 确保使用绝对路径来提供静态文件
const publicPath = path.join(__dirname, 'public');
console.log(`提供静态文件目录: ${publicPath}`);

// 配置CORS - 统一地址但区分环境提示
const allowedOrigins = [
    'http://localhost',
    'http://localhost:3001',
    'http://127.0.0.1',
    'http://127.0.0.1:3001',
    'http://106.53.219.143:3000',
];

const corsOptions = {
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            // 根据环境提供不同的错误信息
            const errorMsg = NODE_ENV === 'production' 
                ? '生产环境：请求来源不被允许'
                : '开发环境：请求来源不在允许列表中';
            
            console.warn('CORS阻止:', {
                environment: NODE_ENV,
                blockedOrigin: origin,
                allowedOrigins: allowedOrigins
            });
            
            callback(new Error(errorMsg));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 204
};

// 请求日志记录 - 先记录所有请求
if (NODE_ENV === 'production') {
    // 生产环境使用combined格式，记录到文件
    const accessLogStream = fs.createWriteStream(
        path.join(__dirname, 'access.log'),
        { flags: 'a' }
    );
    app.use(morgan('combined', { stream: accessLogStream }));
} else {
    // 开发环境使用dev格式，输出到控制台
    app.use(morgan('dev'));
}

// 使用CORS中间件 - 在静态文件服务前使用CORS
app.use(cors(corsOptions));

// 处理预检请求
app.options('*', cors(corsOptions));

// 解析cookie
app.use(cookieParser());

// JSON解析中间件
app.use(express.json({ limit: '1mb' })); // 限制请求体大小

// 应用会话验证中间件到所有路由（除了公开路径）
const publicPaths = ['/verify-code', '/generate-code', '/admin-login', '/logout', '/get-barcode-config', '/generate-barcode'];
app.use((req, res, next) => {
    if (publicPaths.some(path => req.path.startsWith(path)) || 
        req.path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico)$/) ||
        req.path === '/verify.html' || req.path === '/admin.html') {
        return next();
    }
    return sessionAuthMiddleware(req, res, next);
});

// 修改静态文件服务配置，确保HTML文件不被直接访问
app.use((req, res, next) => {
    // 如果请求的是HTML文件，交给后面的路由处理（进行身份验证）
    if (req.url.match(/\.html$/i)) {
        return next();
    }
    // 其他静态资源（CSS、JS、图片等）直接提供
    return express.static(publicPath, {
        maxAge: '1d',
        dotfiles: 'ignore',
        index: false, // 禁用自动索引，手动控制
        redirect: true
    })(req, res, next);
});

// 根路径处理逻辑
app.get('/', (req, res) => {
    const sessionId = req.cookies?.sessionId;
    const sessionData = sessionId ? sessions.get(sessionId) : null;
    
    console.log('根路径访问检查:', {
        sessionId: sessionId ? '存在' : '不存在',
        hasSessionData: !!sessionData,
        sessionValid: sessionData && Date.now() < sessionData.expiryTime,
        ip: req.ip,
        url: req.url
    });
    
    if (sessionData && Date.now() < sessionData.expiryTime) {

        const indexPath = path.join(publicPath, 'index.html');
        return res.sendFile(indexPath);
    } else {
        const verifyPath = path.join(publicPath, 'verify.html');
        
        // 清除可能存在的无效cookie
        if (sessionId) {
            res.clearCookie('sessionId');
        }
        
        return res.sendFile(verifyPath);
    }});

// 添加专门的index.html路由
app.get('/index.html', (req, res) => {
    const sessionId = req.cookies?.sessionId;
    const sessionData = sessionId ? sessions.get(sessionId) : null;
    
    if (sessionData && Date.now() < sessionData.expiryTime) {
        const indexPath = path.join(publicPath, 'index.html');
        return res.sendFile(indexPath);
    } else {
        return res.redirect('/verify.html');
    }});

// 添加verify.html路由
app.get('/verify.html', (req, res) => {
    const verifyPath = path.join(publicPath, 'verify.html');
    res.sendFile(verifyPath);
});

// 添加admin.html路由
app.get('/admin.html', (req, res) => {
    const adminPath = path.join(publicPath, 'admin.html');
    res.sendFile(adminPath);
});



// 安全相关的HTTP头
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

/**
 * HTTP请求日志记录中间件
 * 记录HTTP请求信息并在响应结束后记录响应状态和时间
 */
app.use((req, res, next) => {
    // 只记录静态文件请求的日志
    if (req.url.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i)) {
        log(LOG_LEVELS.DEBUG, '静态文件请求', { url: req.url, ip: req.ip });
        return next();
    }
    
    // 记录请求开始时间
    const start = Date.now();
    
    // 记录请求信息
    const logInfo = {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.headers['user-agent']
    };
    
    // 对敏感路由进行特殊处理
    if (req.url.includes('/admin')) {
        // 敏感路由，不记录太多详细信息
        log(LOG_LEVELS.WARNING, '管理路由访问', { method: req.method, url: req.url, ip: req.ip });
    } else {
        // 普通路由记录详细信息
        log(LOG_LEVELS.INFO, 'HTTP请求', logInfo);
    }
    
    // 监听响应结束
    res.on('finish', () => {
        // 计算响应时间
        const duration = Date.now() - start;
        
        // 构建响应日志
        const responseInfo = {
            method: req.method,
            url: req.url,
            statusCode: res.statusCode,
            duration: `${duration}ms`
        };
        
        // 根据状态码决定日志级别
        if (res.statusCode >= 500) {
            log(LOG_LEVELS.ERROR, 'HTTP响应错误', responseInfo);
        } else if (res.statusCode >= 400) {
            log(LOG_LEVELS.WARNING, 'HTTP响应警告', responseInfo);
        } else {
            log(LOG_LEVELS.DEBUG, 'HTTP响应', responseInfo);
        }
    });
    
    next();
});

/**
 * 设置条码参数的API端点
 * 无需密码验证，可直接修改参数
 */
app.post('/set-barcode-config', sessionAuthMiddleware, async (req, res) => {
    try {
        const { singleBarcodeWidthMm, spacingMm } = req.body;
        
        // 验证并更新用户会话中的条码配置参数
        if (singleBarcodeWidthMm !== undefined) {
            const width = parseFloat(singleBarcodeWidthMm);
            if (isNaN(width) || width <= 0) {
                return res.status(400).json({ error: '单个条码宽度必须是大于0的有效数字' });
            }
            req.session.barcodeConfig.singleBarcodeWidthMm = width;
        }
        
        if (spacingMm !== undefined) {
            const spacing = parseFloat(spacingMm);
            if (isNaN(spacing) || spacing < 0) {
                return res.status(400).json({ error: '条码间隙必须是大于等于0的有效数字' });
            }
            req.session.barcodeConfig.spacingMm = spacing;
        }
        
        // 更新会话存储
        const sessionId = req.cookies.sessionId;
        sessions.update(sessionId, { barcodeConfig: req.session.barcodeConfig });
        
        // 记录配置更新
        log(LOG_LEVELS.INFO, '用户条码配置已更新', { 
            config: req.session.barcodeConfig, 
            sessionId: sessionId.substring(0, 8), 
            updatedBy: req.ip 
        });
        
        res.status(200).json({ 
            success: true, 
            message: '条码参数设置成功', 
            config: req.session.barcodeConfig 
        });
        
    } catch (error) {
        log(LOG_LEVELS.ERROR, '设置条码参数时出错', { error: error.message, stack: error.stack });
        res.status(500).json({ error: '设置参数时发生错误' });
    }});

// 获取当前条码配置的API端点 - 支持返回用户会话配置或默认配置
app.get('/get-barcode-config', async (req, res) => {
    try {
        // 尝试从会话中获取用户特定的配置
        const sessionId = req.cookies?.sessionId;
        let configToReturn = DEFAULT_BARCODE_CONFIG;
        
        // 如果有会话ID，尝试获取用户会话配置
        if (sessionId) {
            const sessionData = sessions.get(sessionId);
            if (sessionData && sessionData.barcodeConfig) {
                configToReturn = sessionData.barcodeConfig;
                log(LOG_LEVELS.DEBUG, '返回用户会话中的条码配置', { 
                    sessionId: sessionId.substring(0, 8),
                    ip: req.ip 
                });
            }
        }
        
        // 否则返回默认配置
        res.status(200).json(configToReturn);
    } catch (error) {
        log(LOG_LEVELS.ERROR, '获取条码配置时出错', { error: error.message, stack: error.stack });
        res.status(500).json({ error: '获取配置时发生错误' });
    }
});

/**
 * 条形码生成API端点
 * 支持生成高质量条形码，可根据宽度需求自动调整条码数量
 * 支持单个条码和多条码拼接模式
 */
app.post('/generate-barcode', async (req, res) => {
    try {
        const { 
            text, 
            width: userWidth,  // 用户输入的总宽度(mm)
            height: userHeight, // 用户输入的条码高度(mm)
            type = 'code128' 
        } = req.body;
        
        // 验证必要参数
        if (!text || typeof text !== 'string') {
            log(LOG_LEVELS.WARNING, '条码生成失败 - 缺少有效内容', { ip: req.ip });
            return res.status(400).json({ error: '请提供有效的条码内容' });
        }
        
        // 验证用户输入的宽度和高度
        if (!userWidth || !userHeight || userWidth <= 0 || userHeight <= 0) {
            log(LOG_LEVELS.WARNING, '条码生成失败 - 无效的尺寸参数', { width: userWidth, height: userHeight, ip: req.ip });
            return res.status(400).json({ error: '请提供有效的宽度和高度值' });
        }
        
        // 固定使用code128格式
        const barcodeType = 'code128';
        
        // 配置高质量图像生成参数
        const DPI = 600; // 高质量DPI设置
        const mmToPx = (mm) => Math.round(mm * DPI / 25.4);
        
        // 获取用户的条码配置（优先从会话中获取，否则使用默认配置）
        const sessionId = req.cookies?.sessionId;
        let userBarcodeConfig = DEFAULT_BARCODE_CONFIG;
        
        if (sessionId) {
            const sessionData = sessions.get(sessionId);
            if (sessionData && sessionData.barcodeConfig) {
                userBarcodeConfig = sessionData.barcodeConfig;
                log(LOG_LEVELS.DEBUG, '使用用户会话中的条码配置', { 
                    sessionId: sessionId.substring(0, 8),
                    config: userBarcodeConfig,
                    ip: req.ip 
                });
            }
        }
        
        // 从用户配置获取参数
        const sideMarginMm = userBarcodeConfig.sideMarginMm;
        const sideMarginPx = mmToPx(sideMarginMm);
        
        // 条码间隙参数
        const spacingMm = userBarcodeConfig.spacingMm;
        const spacingPx = mmToPx(spacingMm);
        
        // 转换用户输入的毫米尺寸为像素
        const totalOutputWidth = mmToPx(parseFloat(userWidth));
        const outputHeight = mmToPx(parseFloat(userHeight));
        
        log(LOG_LEVELS.INFO, '条码生成请求', {
            textLength: text.length,
            width: userWidth,
            height: userHeight,
            dpi: DPI,
            ip: req.ip
        });
        
        log(LOG_LEVELS.DEBUG, '尺寸转换信息', {
            totalOutputWidth: `${totalOutputWidth}px`,
            outputHeight: `${outputHeight}px`,
            dpi: DPI
        });
        
        let count, singleBarcodeWidthPx, actualContentWidth, resultPng;
        
        // 根据用户输入的宽度选择生成模式
        if (userWidth > userBarcodeConfig.singleBarcodeWidthMm) {
            // 多条码模式：用户输入宽度大于配置的单个条码宽度
            const singleBarcodeWidthMm = userBarcodeConfig.singleBarcodeWidthMm;
            singleBarcodeWidthPx = mmToPx(singleBarcodeWidthMm);
            
            // 计算条码数量（考虑间距）
            const availableWidth = totalOutputWidth - 2 * sideMarginPx;
            count = Math.max(1, Math.floor((availableWidth + spacingPx) / (singleBarcodeWidthPx + spacingPx)));
            
            // 计算实际内容宽度（条码+间距）
            actualContentWidth = count * singleBarcodeWidthPx + (count - 1) * spacingPx;
            
            log(LOG_LEVELS.DEBUG, '多条码生成模式', {
                count,
                singleBarcodeWidth: `${singleBarcodeWidthPx}px`,
                contentWidth: `${actualContentWidth}px`
            });
            
        } else {
            // 单条码模式：用户输入宽度小于等于配置的单个条码宽度
            count = 1;
            // 可用宽度 = 总宽度 - 两边间距
            const availableWidth = totalOutputWidth - 2 * sideMarginPx;
            singleBarcodeWidthPx = availableWidth;
            actualContentWidth = singleBarcodeWidthPx;
            
            log(LOG_LEVELS.DEBUG, '单条码生成模式', {
                singleBarcodeWidth: `${singleBarcodeWidthPx}px`
            });
        }
        
        // 生成高质量单个条码
        const singleBarcodeBuffer = await new Promise((resolve, reject) => {
            bwipjs.toBuffer({
                bcid: barcodeType,    // 条码类型
                text: text,           // 条码内容
                scaleX: 6,            // 水平缩放因子 - 高质量设置
                scaleY: Math.max(3, Math.floor(outputHeight / 8)), // 垂直缩放因子
                height: outputHeight, // 条码高度
                includetext: false,   // 不包含文本
                backgroundcolor: 'ffffff', // 白色背景
                foregroundcolor: '000000', // 黑色条码
                paddingwidth: 0,      // 无边距
                paddingheight: 0,
                dotradius: 0.2,       // 点半径 - 提高清晰度
                gs1: false            // 不使用GS1编码
            }, (err, png) => {
                if (err) {
                    log(LOG_LEVELS.ERROR, '生成单个条码失败', { error: err.message });
                    reject(err);
                } else {
                    resolve(png);
                }
            });
        });
        
        // 读取生成的条码图像数据
        const originalPng = PNG.sync.read(singleBarcodeBuffer);
        const originalWidth = originalPng.width;
        const originalHeight = originalPng.height;
        const pixelData = originalPng.data;
        
        log(LOG_LEVELS.DEBUG, '原始条码尺寸', {
            width: `${originalWidth}px`,
            height: `${originalHeight}px`
        });
        
        // 记录缩放需求
        if (originalWidth !== singleBarcodeWidthPx) {
            log(LOG_LEVELS.DEBUG, '需要进行条码缩放', {
                sourceWidth: `${originalWidth}px`,
                targetWidth: `${singleBarcodeWidthPx}px`
            });
        }
        
        // 创建最终输出图像
        resultPng = new PNG({
            width: totalOutputWidth,
            height: outputHeight,
            colorType: 2, // RGB色彩模式
            bgColor: { red: 255, green: 255, blue: 255 } // 白色背景
        });
        
        // 填充白色背景
        for (let i = 0; i < resultPng.data.length; i += 4) {
            resultPng.data[i] = 255;     // R
            resultPng.data[i + 1] = 255; // G
            resultPng.data[i + 2] = 255; // B
            resultPng.data[i + 3] = 255; // A
        }
        
        // 计算水平起始位置（居中显示内容）
        const startX = Math.floor((totalOutputWidth - actualContentWidth) / 2);
        
        // 高质量条码生成和拼接循环
        for (let i = 0; i < count; i++) {
            // 计算当前条码在输出图像中的起始X坐标
            const barcodeStartX = startX + i * (singleBarcodeWidthPx + (count > 1 ? spacingPx : 0));
            
            // 高质量缩放复制条码像素数据
            for (let y = 0; y < outputHeight; y++) {
                // 高质量垂直缩放：使用线性映射
                const srcY = Math.min(
                    Math.round((y / outputHeight) * originalHeight), 
                    originalHeight - 1
                );
                
                for (let x = 0; x < singleBarcodeWidthPx; x++) {
                    // 高质量水平缩放
                    const srcX = Math.min(
                        Math.round((x / singleBarcodeWidthPx) * originalWidth),
                        originalWidth - 1
                    );
                    
                    // 计算源图像和目标图像的像素索引
                    const srcIdx = (srcY * originalWidth + srcX) * 4;
                    const destIdx = (y * totalOutputWidth + barcodeStartX + x) * 4;
                    
                    // 高质量像素复制：使用阈值判断条码像素
                    const isBarCodePixel = (
                        pixelData[srcIdx] < 200 || 
                        pixelData[srcIdx + 1] < 200 || 
                        pixelData[srcIdx + 2] < 200
                    );
                    
                    if (isBarCodePixel) {
                        // 条码像素 - 使用纯黑色确保扫描清晰度
                        resultPng.data[destIdx] = 0;         // R
                        resultPng.data[destIdx + 1] = 0;     // G
                        resultPng.data[destIdx + 2] = 0;     // B
                        resultPng.data[destIdx + 3] = 255;   // A
                    }
                    // 背景保持白色，不处理
                }
            }
            
            // 绘制条码之间的间距（只在多个条码时）
            if (count > 1 && i < count - 1) {
                const spacingStartX = barcodeStartX + singleBarcodeWidthPx;
                for (let y = 0; y < outputHeight; y++) {
                    for (let x = 0; x < spacingPx; x++) {
                        const destIdx = (y * totalOutputWidth + spacingStartX + x) * 4;
                        // 纯白色间距
                        resultPng.data[destIdx] = 255;     // R
                        resultPng.data[destIdx + 1] = 255; // G
                        resultPng.data[destIdx + 2] = 255; // B
                        resultPng.data[destIdx + 3] = 255; // A
                    }
                }
            }
        }
        
        // 将生成的图像转换为缓冲区
        const resultBuffer = PNG.sync.write(resultPng);
        
        // 生成安全的文件名
        const sanitizedText = text.replace(/[^a-zA-Z0-9]/g, '_');
        const fileName = `${sanitizedText}(${userWidth}x${userHeight}).png`;
        
        // 设置响应头信息
        res.set({
            'Content-Type': 'image/png',
            'Content-Length': resultBuffer.length,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'X-Image-Resolution': `${totalOutputWidth}x${outputHeight}`,
            'X-Barcode-Repeats': count,
            'X-Barcode-Spacing': count > 1 ? `${spacingMm}mm` : '0mm',
            'X-Side-Margin': `${sideMarginMm}mm`,
            'X-User-Input': `width:${userWidth}mm, height:${userHeight}mm`,
            'X-Mode': userWidth > 50 ? 'multi-barcode' : 'single-barcode',
            'X-DPI': DPI
        });
        
        log(LOG_LEVELS.INFO, '条码生成成功', {
            mode: userWidth > 50 ? 'multi-barcode' : 'single-barcode',
            count,
            dimensions: `${totalOutputWidth}x${outputHeight}px`,
            dpi: DPI
        });
        
        // 发送生成的图像
        res.send(resultBuffer);
        
    } catch (error) {
        log(LOG_LEVELS.ERROR, '生成条形码时出错', { 
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        res.status(500).json({ error: `生成条形码时出错: ${error.message}` });
    }
});

// 启动定期清理任务
startCleanupTasks();

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在 http://localhost:${PORT}`);
    console.log(`静态文件目录: ${publicPath}`);
    console.log('验证码系统已启用，管理员密码: keda666');
});


// 管理员密码验证中间件 - 用于保护验证码生成
function adminAuthMiddleware(req, res, next) {
    const password = req.body?.password || req.query?.password;
    
    if (!password) {
        return res.status(400).json({ error: '密码不能为空' });
    }
    
    if (password !== ADMIN_PASSWORD) {
        log(LOG_LEVELS.SECURITY, '管理员密码验证失败', { ip: req.ip });
        return res.status(401).json({ error: '密码错误' });
    }
    
    next();
}

/**
 * 会话验证中间件 - 确保只有验证过的用户可以访问功能
 * @param {Object} req - Express请求对象
 * @param {Object} res - Express响应对象
 * @param {Function} next - Express下一个中间件函数
 */
function sessionAuthMiddleware(req, res, next) {
    try {
        // 不需要验证的路径
        const publicPaths = [
            '/verify-code', 
            '/admin-login', 
            '/logout', 
            '/get-barcode-config', 
            '/generate-barcode',
            '/verify.html'
        ];
        
        // 公共路径或静态资源直接通过
        if (publicPaths.some(path => req.path === path) || 
            req.path.match(/\.(js|css|png|jpg|jpeg|gif|svg|ico)$/) ||
            req.path === '/admin.html') {
            return next();
        }
        
        // 对于根路径和index.html，已经单独处理，这里跳过
        if (req.path === '/' || req.path === '/index.html') {
            return next();
        }
        
        // 检查会话cookie
        const sessionId = req.cookies?.sessionId;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        log(LOG_LEVELS.DEBUG, '会话验证中间件检查', {
            path: req.path,
            sessionId: sessionId ? '存在' : '不存在',
            clientIp
        });
        
        // 会话ID不存在的处理
        if (!sessionId) {
            // 尝试从请求头中获取会话ID
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                sessionId = authHeader.substring(7);
            }
            
            // 如果仍然没有会话ID，返回错误
            if (!sessionId) {
                log(LOG_LEVELS.WARNING, '会话验证失败 - 未提供会话ID', { ip: clientIp, url: req.url });
                
                // 对于API请求，返回JSON错误，不重定向
                if (req.path.startsWith('/admin/') || req.path.startsWith('/api/')) {
                    return res.status(401).json({ 
                        error: '未授权访问，请先登录',
                        requiresVerification: true 
                    });
                }
                
                if (req.accepts('html')) {
                    return res.redirect('/verify.html');
                }
                return res.status(401).json({ 
                    error: '未授权访问，请先验证验证码',
                    requiresVerification: true 
                });
            }
        }
        
        // 验证会话是否存在
        const sessionData = sessions.get(sessionId);
        if (!sessionData) {
            log(LOG_LEVELS.WARNING, '会话验证失败 - 会话不存在', { ip: clientIp, url: req.url });
            
            // 清除无效Cookie
            res.clearCookie('sessionId');
            
            // 对于API请求，返回JSON错误，不重定向
            if (req.path.startsWith('/admin/') || req.path.startsWith('/api/')) {
                return res.status(401).json({ 
                    error: '会话不存在，请重新登录',
                    requiresVerification: true 
                });
            }
            
            if (req.accepts('html')) {
                return res.redirect('/verify.html');
            }
            return res.status(401).json({ 
                error: '会话不存在，请重新验证验证码',
                requiresVerification: true 
            });
        }
        
        // 检查会话是否过期
        if (Date.now() > sessionData.expiryTime) {
            log(LOG_LEVELS.WARNING, '会话验证失败 - 会话已过期', { ip: clientIp, url: req.url });
            
            // 删除过期会话
            sessions.delete(sessionId);
            res.clearCookie('sessionId');
            
            // 对于API请求，返回JSON错误，不重定向
            if (req.path.startsWith('/admin/') || req.path.startsWith('/api/')) {
                return res.status(401).json({ 
                    error: '会话已过期，请重新登录',
                    requiresVerification: true 
                });
            }
            
            if (req.accepts('html')) {
                return res.redirect('/verify.html');
            }
            return res.status(401).json({ 
                error: '会话已过期，请重新验证验证码',
                requiresVerification: true 
            });
        }
        
        // 验证通过，更新会话活动时间并延长会话过期时间
        const sessionExpiryDays = sessionData.sessionExpiryDays;
        let newExpiryTime;
        
        if (sessionExpiryDays === null || sessionExpiryDays === undefined) {
            // 永久有效会话，保持不变
            newExpiryTime = sessionData.expiryTime;
        } else {
            // 延长会话过期时间
            newExpiryTime = Date.now() + sessionExpiryDays * 24 * 60 * 60 * 1000;
        }
        
        sessions.update(sessionId, {
            lastActivity: Date.now(),
            expiryTime: newExpiryTime
        });
        
        // 同时更新cookie的过期时间
        res.cookie('sessionId', sessionId, {
            maxAge: newExpiryTime - Date.now(),
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: NODE_ENV === 'production' ? 'strict' : 'lax',
            path: '/',
            domain: undefined
        });
        
        log(LOG_LEVELS.DEBUG, '会话验证成功', { sessionId: sessionId.substring(0, 8), ip: clientIp });
        
        // 将会话数据附加到请求对象
        req.session = sessionData;
        next();
        
    } catch (error) {
        log(LOG_LEVELS.ERROR, '会话验证错误', { error: error.message, stack: error.stack });
        return res.status(500).json({ error: '服务器错误' });
    }
}

/**
 * 生成验证码API端点
 * 由管理员使用，用于创建临时验证码
 * 包含速率限制、IP锁定保护和过期时间验证
 * 
 * @name /generate-code
 * @route {POST} /generate-code
 * @middleware sessionAuthMiddleware - 确保只有已验证用户可访问
 * @param {Object} req.body - 请求参数
 * @param {number} req.body.hours - 验证码有效期（小时），默认使用配置值
 * @returns {Object} 验证码和过期时间
 */
app.post('/generate-code', sessionAuthMiddleware, async (req, res) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress;
        const { hours = VERIFICATION_CONFIG.defaultExpiryHours, sessionExpiryDays } = req.body;
        
        // 记录验证码生成尝试
        log(LOG_LEVELS.SECURITY, '验证码生成尝试', {
            clientIp,
            siteName: req.body.siteName,
            sessionExpiryDays: req.body.sessionExpiryDays
        });
        
        // 检查IP是否被锁定（即使是管理员也适用速率限制）
        if (isIpLocked(clientIp)) {
            const remainingTime = Math.ceil((lockedIps[clientIp].unlockTime - Date.now()) / 60000);
            
            log(LOG_LEVELS.SECURITY, '验证码生成失败 - IP已锁定', {
                clientIp,
                remainingMinutes: remainingTime
            });
            
            return res.status(429).json({ error: `请求过于频繁，请${remainingTime}分钟后再试` });
        }
        
        // 验证过期时间参数
        const expiryTime = parseFloat(hours);
        if (isNaN(expiryTime) || expiryTime <= 0 || expiryTime > 168) { // 最大7天
            log(LOG_LEVELS.WARNING, '验证码生成失败 - 无效的过期时间', {
                clientIp,
                requestedHours: hours
            });
            
            return res.status(400).json({ error: '请提供有效的过期时间（大于0小时，最多168小时）' });
        }
        
        // 生成验证码
        const code = generateVerificationCode();
        const expiryDate = new Date();
        // 确保正确处理小数值的小时，使用毫秒计算更精确
        expiryDate.setTime(expiryDate.getTime() + expiryTime * 60 * 60 * 1000);
        
        // 验证现场名称不能为空
        if (!req.body.siteName || req.body.siteName.trim() === '') {
            return res.status(400).json({ error: '现场名称不能为空' });
        }
        
        // 存储验证码信息
        verificationCodes.add(code, {
            expiry: expiryDate,
            attempts: 0,
            used: false,
            generatedByIp: clientIp,
            expiryHours: expiryTime,
            siteName: req.body.siteName.trim(),
            sessionExpiryDays: sessionExpiryDays // 保存会话过期天数，null表示永久
        });
        
        // 记录成功生成
        log(LOG_LEVELS.SECURITY, '验证码生成成功', {
            clientIp,
            code: code.substring(0, 1) + '*'.repeat(code.length - 1), // 部分隐藏敏感信息
            expiryHours: expiryTime,
            expiry: expiryDate.toISOString()
        });
        
        // 返回生成的验证码
        res.status(200).json({
            success: true,
            code,
            expiryTime: expiryDate.getTime()
        });
    } catch (error) {
        log(LOG_LEVELS.ERROR, '生成验证码错误', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        res.status(500).json({ error: '服务器错误' });
    }
});

// 检查IP是否被锁定
function isIpLocked(ip) {
    const lockInfo = lockedIps[ip];
    if (!lockInfo) return false;
    
    const now = Date.now();
    if (now > lockInfo.unlockTime) {
        // 锁定时间已过，解除锁定
        log(LOG_LEVELS.INFO, 'IP锁定过期，自动解锁', {
            ip,
            lockedDurationMinutes: Math.floor((now - lockInfo.lockTime) / 60000)
        });
        delete lockedIps[ip];
        return false;
    }
    
    return true;
}

// 检查并更新IP访问记录，返回是否允许请求
function checkRateLimit(ip) {
    const now = Date.now();
    
    if (!ipAccessRecords[ip]) {
        ipAccessRecords[ip] = [];
    }
    
    // 清理过期的访问记录
    ipAccessRecords[ip] = ipAccessRecords[ip].filter(timestamp => 
        now - timestamp < VERIFICATION_CONFIG.rateLimitWindowMs
    );
    
    const currentRequests = ipAccessRecords[ip].length;
    
    // 检查是否超出请求限制
    if (currentRequests >= VERIFICATION_CONFIG.maxRequestsPerWindow) {
        // 锁定IP
        lockedIps[ip] = {
            lockTime: now,
            unlockTime: now + VERIFICATION_CONFIG.lockoutMinutes * 60 * 1000
        };
        
        log(LOG_LEVELS.SECURITY, '速率限制被触发，IP已锁定', {
            ip,
            currentRequests,
            maxRequests: VERIFICATION_CONFIG.maxRequestsPerWindow,
            windowMs: VERIFICATION_CONFIG.rateLimitWindowMs,
            lockoutMinutes: VERIFICATION_CONFIG.lockoutMinutes,
            unlockTime: new Date(lockedIps[ip].unlockTime).toISOString()
        });
        
        return false;
    }
    
    // 记录本次访问
    ipAccessRecords[ip].push(now);
    
    // 记录接近限制的请求（超过75%）
    if (currentRequests >= VERIFICATION_CONFIG.maxRequestsPerWindow * 0.75) {
        log(LOG_LEVELS.WARN, '请求频率接近限制', {
            ip,
            currentRequests,
            maxRequests: VERIFICATION_CONFIG.maxRequestsPerWindow,
            remainingRequests: VERIFICATION_CONFIG.maxRequestsPerWindow - currentRequests
        });
    }
    
    return true;
}

/**
 * 验证验证码API端点
 * 验证用户提供的验证码，支持速率限制、IP锁定和会话创建
 * 
 * @name /verify-code
 * @route {POST} /verify-code
 * @param {Object} req.body - 请求参数
 * @param {string} req.body.code - 需要验证的验证码
 * @returns {Object} 验证结果和会话信息
 */
app.post('/verify-code', async (req, res) => {
    try {
        const { code } = req.body || {};
        const clientIp = req.ip || req.connection.remoteAddress;
        
        // 记录验证尝试
        logUserAuth('验证码验证尝试', clientIp);
        
        // 检查IP是否被锁定
        if (isIpLocked(clientIp)) {
            const remainingTime = Math.ceil((lockedIps[clientIp].unlockTime - Date.now()) / 60000);
            
            logUserAuth('验证码验证失败 - IP已锁定', clientIp);
            
            return res.status(429).json({ 
                error: `请求过于频繁，请${remainingTime}分钟后再试` 
            });
        }
        
        // 检查请求速率限制
        if (!checkRateLimit(clientIp)) {
            logUserAuth('验证码验证失败 - 请求频率过高', clientIp);
            
            return res.status(429).json({ 
                error: '请求过于频繁，请稍后再试' 
            });
        }
        
        // 验证验证码格式
        if (!code || typeof code !== 'string' || code.length !== VERIFICATION_CONFIG.CODE_LENGTH || !/^\d+$/.test(code)) {
            logUserAuth('验证码验证失败 - 无效格式', clientIp);
            
            return res.status(400).json({ error: '验证码格式错误，请输入4位数字' });
        }
        
        // 检查验证码是否存在
        const codeInfo = verificationCodes.get(code);
        
        if (!codeInfo) {
            logUserAuth('验证码验证失败 - 不存在', clientIp);
            
            return res.status(401).json({ error: '验证码不存在或已过期' });
        }
        
        // 增加尝试次数
        verificationCodes.update(code, { 
            attempts: (codeInfo.attempts || 0) + 1 
        });
        
        // 检查是否已使用
        if (codeInfo.used) {
            logUserAuth('验证码验证失败 - 已使用', clientIp);
            
            return res.status(401).json({ error: '验证码已被使用' });
        }
        
        // 检查是否过期
        if (new Date() > codeInfo.expiry) {
            logUserAuth('验证码验证失败 - 已过期', clientIp);
            
            return res.status(401).json({ error: '验证码已过期' });
        }
        
        // 检查尝试次数是否超过限制
        if ((codeInfo.attempts || 0) >= VERIFICATION_CONFIG.MAX_ATTEMPTS) {
            logUserAuth('验证码验证失败 - 尝试次数过多', clientIp);
            
            return res.status(401).json({ error: '验证码尝试次数过多' });
        }
        
        // 验证成功，创建会话
        const sessionId = createSessionId();
        let sessionExpiry;
        let maxAge;
        
        // 根据验证码中的sessionExpiryDays设置会话过期时间
        if (codeInfo.sessionExpiryDays === null || codeInfo.sessionExpiryDays === undefined) {
            // 永久有效（设置为100年）
            sessionExpiry = Date.now() + 100 * 365 * 24 * 60 * 60 * 1000;
            maxAge = 100 * 365 * 24 * 60 * 60 * 1000;
        } else {
            // 根据天数计算过期时间
            const sessionExpiryDays = parseInt(codeInfo.sessionExpiryDays) || 7;
            sessionExpiry = Date.now() + sessionExpiryDays * 24 * 60 * 60 * 1000;
            maxAge = sessionExpiryDays * 24 * 60 * 60 * 1000;
        }
        
        // 存储会话信息，包含用户独立的条码配置和现场名称
        sessions.add(sessionId, {
            verificationCode: code,
            expiryTime: sessionExpiry,
            clientIp: clientIp,
            verifiedAt: Date.now(),
            siteName: codeInfo.siteName,
            barcodeConfig: { ...DEFAULT_BARCODE_CONFIG } // 初始化用户独立的条码配置
        });

        // 适应代理环境的Cookie设置
        res.cookie('sessionId', sessionId, {
            maxAge: maxAge,
            httpOnly: true,
            secure: NODE_ENV === 'production', // 根据环境设置secure属性
            sameSite: NODE_ENV === 'production' ? 'strict' : 'lax', // 根据环境设置sameSite属性
            path: '/', // 确保cookie在所有路径下都能访问
            domain: undefined // 不设置domain，自动使用当前域名
        });



        // 返回成功响应
        res.status(200).json({
            success: true,
            message: '验证成功',
            sessionId,
            redirectUrl: '/'
        });

    } catch (error) {
        // 使用统一的错误日志记录
        log(LOG_LEVELS.ERROR, '验证码验证失败', {
            error: error.message,
            stack: error.stack,
            path: req.path,
            method: req.method,
            ip: req.ip || req.connection.remoteAddress,
            body: req.body
        });
        
        // 返回错误响应
        res.status(500).json({ error: '服务器错误' });
    }
});

/**
 * 会话状态检查API端点
 * 验证当前用户会话是否有效
 * 
 * @name /check-session
 * @route {GET} /check-session
 * @returns {Object} 包含会话有效性和会话ID的对象
 */
app.get('/check-session', (req, res) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress;
        const sessionId = req.cookies?.sessionId;
        const sessionData = sessionId ? sessions.get(sessionId) : null;
        
        const isValid = sessionData && Date.now() < sessionData.expiryTime;
        
        // 使用统一的日志记录函数
        log(LOG_LEVELS.INFO, '会话状态检查', {
            clientIp,
            sessionIdExists: !!sessionId,
            isValid: isValid,
            sessionIdFragment: sessionId ? sessionId.substring(0, 8) + '...' : null
        });
        
        // 返回会话状态
        res.json({ 
            valid: isValid,
            sessionId: sessionId
        });
    } catch (error) {
        // 使用统一的错误日志记录
        log(LOG_LEVELS.ERROR, '会话状态检查错误', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        res.json({ valid: false });
    }
});

/**
 * 管理员登录API端点
 * 提供管理员密码登录功能，作为验证码验证的替代方式
 * 
 * @name /admin-login
 * @route {POST} /admin-login
 * @param {Object} req.body - 请求参数
 * @param {string} req.body.password - 管理员密码
 * @returns {Object} 登录结果和会话信息
 */
app.post('/admin-login', async (req, res) => {
    try {
        const { password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        
        // 验证密码
        if (!password) {
            return res.status(400).json({ error: '密码不能为空' });
        }
        
        if (password !== ADMIN_PASSWORD) {
            return res.status(401).json({ error: '密码错误' });
        }
        
        // 创建新的管理员会话
        const sessionId = createSessionId();
        const ONE_WEEK_MS = 24 * 7 * 60 * 60 * 1000; // 7天
        const sessionExpiry = Date.now() + ONE_WEEK_MS;
        
        // 存储会话信息
        sessions.add(sessionId, {
            expiryTime: sessionExpiry,
            isAdmin: true,
            loggedInAt: Date.now(),
            clientIp: clientIp,
            barcodeConfig: { ...DEFAULT_BARCODE_CONFIG },
            metadata: {
                createdTimestamp: Date.now(),
                lastAccessed: Date.now(),
                accessCount: 1
            }
        });
        
        // 设置Cookie 
        const cookieOptions = {
            maxAge: ONE_WEEK_MS,
            httpOnly: true,
            secure: NODE_ENV === 'production',
            sameSite: NODE_ENV === 'production' ? 'strict' : 'lax',
            path: '/'  // 确保在根路径下可访问
        };
        
        // 如果是本地开发环境，放松sameSite限制
        if (NODE_ENV === 'development') {
            cookieOptions.sameSite = 'lax';
        }
        
        res.cookie('sessionId', sessionId, cookieOptions);
        
        res.status(200).json({
            success: true,
            message: '管理员登录成功',
            sessionId: sessionId
        });
        
    } catch (error) {
        res.status(500).json({ error: '登录失败' });
    }
});

/**
 * 管理员登出API端点
 * 销毁当前用户会话并清除cookie
 * 
 * @name /logout
 * @route {POST} /logout
 * @returns {Object} 登出结果
 */
app.post('/logout', async (req, res) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress;
        // 获取会话ID
        const sessionId = req.cookies?.sessionId;
        
        // 删除会话
        if (sessionId) {
            sessions.delete(sessionId);
            // 使用统一的日志记录函数
            log(LOG_LEVELS.INFO, '用户登出，删除会话', {
                clientIp,
                sessionIdFragment: sessionId.substring(0, 8) + '...'
            });
        }
        
        // 清除会话cookie
        res.clearCookie('sessionId');
        
        return res.json({ success: true, message: '登出成功' });
        
    } catch (error) {
        // 使用统一的错误日志记录
        log(LOG_LEVELS.ERROR, '登出失败', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        return res.status(500).json({ error: '服务器错误' });
    }
});

/**
 * 管理员状态检查API端点
 * 验证当前会话是否为管理员会话并返回系统统计信息
 * 
 * @name /admin-status
 * @route {GET} /admin-status
 * @returns {Object} 管理员状态和系统统计信息
 */
/**
 * 修改管理员状态检查端点
 */
app.get('/admin-status', (req, res) => {
    try {
        
        const sessionId = req.cookies?.sessionId;
        
        if (!sessionId) {
            return res.json({ isAdmin: false });
        }
        
        const sessionData = sessions.get(sessionId);
        
        if (!sessionData) {
            return res.json({ isAdmin: false });
        }
        
        // 检查会话是否过期
        if (Date.now() > sessionData.expiryTime) {
            sessions.delete(sessionId);
            // 清除cookie
            res.clearCookie('sessionId', {
                path: '/',
                httpOnly: true,
                secure: NODE_ENV === 'production'
            });
            return res.json({ isAdmin: false });
        }
        
        // 检查是否为管理员会话
        if (!sessionData.isAdmin) {
            return res.json({ isAdmin: false });
        }
        
        // 更新最后活动时间（滑动过期）
        sessions.update(sessionId, {
            lastActivity: Date.now()
        });
        
        // 获取统计信息
        const sessionStats = sessions.getStats();
        const codeStats = verificationCodes.getStats();
        
        const stats = {
            activeUsers: sessionStats.activeUsers,
            activeCodes: codeStats.activeCodes,
            totalSessions: sessionStats.total,
            adminSessions: sessionStats.adminSessions,
            totalCodes: codeStats.total,
            usedCodes: codeStats.used
        };
        
        
        res.json({
            isAdmin: true,
            stats: stats
        });
        
    } catch (error) {
        res.json({ isAdmin: false });
    }
});

/**
 * 获取所有用户会话API端点
 * 仅管理员可访问，用于查看所有当前活跃的用户会话
 * 
 * @name /admin/get-all-sessions
 * @route {GET} /admin/get-all-sessions
 * @returns {Object} 包含所有会话信息的对象
 */
app.get('/admin/get-all-sessions', sessionAuthMiddleware, async (req, res) => {
    try {
        // 检查是否为管理员
        const sessionId = req.cookies?.sessionId;
        const sessionData = sessions.get(sessionId);
        if (!sessionData || !sessionData.isAdmin) {
            return res.status(403).json({ error: '权限不足' });
        }
        
        // 获取所有会话
        const allSessions = sessions.getAll();
        
        // 格式化会话数据，便于前端展示
        const formattedSessions = Object.entries(allSessions).map(([sessionId, session]) => ({
            sessionId,
            siteName: session.siteName || '默认现场',
            verificationCode: session.verificationCode,
            expiryTime: session.expiryTime,
            verifiedAt: session.verifiedAt,
            clientIp: session.clientIp,
            isExpired: Date.now() > session.expiryTime,
            metadata: session.metadata
        }));
        
        // 记录管理员操作
        log(LOG_LEVELS.INFO, '管理员获取所有会话', {
            ip: req.ip,
            sessionCount: formattedSessions.length
        });
        
        res.status(200).json({
            success: true,
            sessions: formattedSessions
        });
    } catch (error) {
        log(LOG_LEVELS.ERROR, '获取所有会话错误', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        res.status(500).json({ error: '服务器错误' });
    }
});

/**
 * 停用用户会话API端点
 * 仅管理员可访问，用于停用特定用户会话
 * 
 * @name /admin/deactivate-session
 * @route {POST} /admin/deactivate-session
 * @param {Object} req.body - 请求参数
 * @param {string} req.body.sessionId - 要停用的会话ID
 * @returns {Object} 包含操作结果的对象
 */
app.post('/admin/deactivate-session', sessionAuthMiddleware, async (req, res) => {
    try {
        // 检查是否为管理员
        const sessionId = req.cookies?.sessionId;
        const sessionData = sessions.get(sessionId);
        if (!sessionData || !sessionData.isAdmin) {
            return res.status(403).json({ error: '权限不足' });
        }
        
        const { sessionId: targetSessionId } = req.body;
        if (!targetSessionId) {
            return res.status(400).json({ error: '缺少会话ID' });
        }
        
        // 检查目标会话是否存在
        const targetSession = sessions.get(targetSessionId);
        if (!targetSession) {
            return res.status(404).json({ error: '会话不存在' });
        }
        
        // 删除目标会话
        sessions.delete(targetSessionId);
        
        // 记录管理员操作
        log(LOG_LEVELS.INFO, '管理员停用用户会话', {
            ip: req.ip,
            targetSessionId: targetSessionId.substring(0, 8) + '...',
            siteName: targetSession.siteName
        });
        
        res.status(200).json({
            success: true,
            message: '会话已成功停用',
            sessionId: targetSessionId
        });
    } catch (error) {
        log(LOG_LEVELS.ERROR, '停用会话错误', {
            error: error.message,
            stack: error.stack,
            ip: req.ip
        });
        res.status(500).json({ error: '服务器错误' });
    }
});

/**
 * 全局错误处理中间件
 * 捕获所有未处理的错误并返回统一的错误响应
 */
app.use((err, req, res, next) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    // 记录错误信息
    log(LOG_LEVELS.ERROR, '未捕获的错误', {
        error: err.message,
        stack: err.stack,
        ip: clientIp,
        path: req.path,
        method: req.method
    });
    
    // 返回统一格式的错误响应
    res.status(500).json({ error: '服务器内部错误' });
});

/**
 * 404处理中间件
 * 处理所有未匹配的路由请求
 */
app.use((req, res) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    // 记录404请求
    log(LOG_LEVELS.INFO, '404 资源未找到', {
        ip: clientIp,
        path: req.path,
        method: req.method
    });
    
    res.status(404).json({ error: '请求的资源不存在' });
});

/**
 * 进程信号处理
 * 实现服务器的优雅关闭
 */
process.on('SIGTERM', () => {
    log(LOG_LEVELS.INFO, '收到终止信号(SIGTERM)，正在关闭服务器...');
    // 清理资源
    console.log('清理中...');
    // 可以在这里添加：关闭数据库连接、保存会话数据等清理操作
    console.log('清理完成，服务器已关闭');
    process.exit(0);
});

process.on('SIGINT', () => {
    log(LOG_LEVELS.INFO, '收到中断信号(SIGINT)，正在关闭服务器...');
    // 清理资源
    console.log('清理中...');
    // 可以在这里添加：关闭数据库连接、保存会话数据等清理操作
    console.log('清理完成，服务器已关闭');
    process.exit(0);
});