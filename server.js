const express = require('express');
const cors = require('cors');
const bwipjs = require('bwip-js');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
// 使用pngjs库处理PNG图像，实现像素级操作
const { PNG } = require('pngjs');

const app = express();
const PORT = process.env.PORT || 3001;
const NODE_ENV = process.env.NODE_ENV || 'development';

// 确保使用绝对路径来提供静态文件
const publicPath = path.join(__dirname, 'public');
console.log(`提供静态文件目录: ${publicPath}`);

// 配置CORS - 更灵活的配置确保跨域请求正常工作
const corsOptions = {
    origin: function(origin, callback) {
        // 开发环境或直接通过IP访问时允许所有来源
        if (NODE_ENV !== 'production' || !origin) {
            return callback(null, true);
        }
        
        // 生产环境允许的来源列表
        const allowedOrigins = [
            'http://106.53.219.143', 
            'http://106.53.219.143:80', 
            'http://106.53.219.143:3000', 
            'http://106.53.219.143:3001',
            'http://localhost',
            'http://localhost:3000',
            'http://localhost:3001'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.warn(`CORS错误: 不允许的源 ${origin}`);
            callback(new Error('不允许的跨域请求'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200
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

// JSON解析中间件
app.use(express.json({ limit: '1mb' })); // 限制请求体大小

// 静态文件服务 - 确保这是在其他路由之前配置的
app.use(express.static(publicPath, {
    maxAge: NODE_ENV === 'production' ? '1d' : 0, // 生产环境设置静态文件缓存
    dotfiles: 'ignore',
    index: ['index.html'], // 正确的index配置
    redirect: true
}));

// 处理根路径请求 - 当静态文件服务无法处理时的备用方案
app.get('/', (req, res) => {
    const indexPath = path.join(publicPath, 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        console.error(`找不到index.html文件: ${indexPath}`);
        res.status(404).send('找不到页面');
    }
});

// 检查public目录是否存在（使用绝对路径）
if (!fs.existsSync(publicPath)) {
    try {
        fs.mkdirSync(publicPath, { recursive: true });
        console.log(`创建public目录: ${publicPath}`);
    } catch (error) {
        console.error(`创建public目录失败: ${error.message}`);
    }
}

// 安全相关的HTTP头
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// 添加更详细的静态文件访问日志
app.use((req, res, next) => {
    // 只记录静态文件请求的日志
    if (req.url.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i)) {
        console.log(`静态文件请求: ${req.url}`);
    }
    next();
});

// 条形码生成API端点
app.post('/generate-barcode', async (req, res) => {
    try {
        const { text, width, height, type = 'code128', targetWidth = 17703, targetHeight = 64, defaultWidth = 300, defaultMargin = 10 } = req.body;
        
        if (!text || typeof text !== 'string') {
            return res.status(400).json({ error: '请提供有效的条码内容' });
        }
        
        const barcodeType = 'code128';
        const outputWidth = Number(targetWidth) || 17703;
        const outputHeight = Number(targetHeight) || 64;
        
        // 条码间距设置（8mm，更明显）
        const spacingMm = 8;
        const spacingPx = Math.round(spacingMm * 3.78); // 约30像素
        
        // 生成单个条码（保留少量内边距）
        const singleBarcodeBuffer = await new Promise((resolve, reject) => {
            bwipjs.toBuffer({
                bcid: barcodeType,    
                text: text,           
                scaleX: 9,            
                scaleY: Math.max(2, outputHeight / 20), 
                includetext: false,   
                backgroundcolor: 'ffffff',
                foregroundcolor: '000000',
                paddingwidth: 5,  // 少量内边距避免条码边缘裁切
                paddingheight: 5,
                dotradius: 0.3,       
                gs1: false            
            }, (err, png) => {
                if (err) reject(err);
                else resolve(png);
            });
        });
        
        const png = PNG.sync.read(singleBarcodeBuffer);
        const singleWidth = png.width;
        const singleHeight = png.height;
        const pixelData = png.data; 
        
        // 计算条码数量（扣除间距）
        const count = Math.max(1, Math.floor((outputWidth + spacingPx) / (singleWidth + spacingPx)));
        
        // 总宽度
        const totalWidth = count * singleWidth + (count - 1) * spacingPx;
        
        // 创建最终图像
        const resultPng = new PNG({
            width: totalWidth,
            height: outputHeight,
            colorType: 2, 
            bgColor: { red: 255, green: 255, blue: 255 }
        });
        
        // 拼接条码（带明显间距）
        for (let y = 0; y < outputHeight; y++) {
            let currentX = 0;
            for (let i = 0; i < count; i++) {
                // 绘制条码
                for (let x = 0; x < singleWidth; x++) {
                    const srcY = Math.min(y, singleHeight - 1);
                    const srcIdx = (srcY * singleWidth + x) * 4;
                    const destIdx = (y * totalWidth + currentX + x) * 4;
                    
                    resultPng.data[destIdx] = pixelData[srcIdx];         
                    resultPng.data[destIdx + 1] = pixelData[srcIdx + 1]; 
                    resultPng.data[destIdx + 2] = pixelData[srcIdx + 2]; 
                    resultPng.data[destIdx + 3] = pixelData[srcIdx + 3]; 
                }
                
                // 绘制明显的间距（8mm）
                if (i < count - 1) {
                    for (let x = 0; x < spacingPx; x++) {
                        const destIdx = (y * totalWidth + currentX + singleWidth + x) * 4;
                        // 可以用浅灰色突出间距（可选）
                        resultPng.data[destIdx] = 240;     
                        resultPng.data[destIdx + 1] = 240; 
                        resultPng.data[destIdx + 2] = 240; 
                        resultPng.data[destIdx + 3] = 255; 
                    }
                }
                
                currentX += singleWidth + spacingPx;
            }
        }
        
        const resultBuffer = PNG.sync.write(resultPng);
        
        // 生成符合要求的文件名：条码文本(宽度x数量).png
        const sanitizedText = text.replace(/[^a-zA-Z0-9]/g, '_');
        const fileName = `${sanitizedText}(${totalWidth}x${count}).png`;
        
        res.set({
            'Content-Type': 'image/png',
            'Content-Length': resultBuffer.length,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'X-Image-Resolution': `${totalWidth}x${outputHeight}`,
            'X-Barcode-Repeats': count,
            'X-Barcode-Spacing': `${spacingMm}mm`
        });
        res.send(resultBuffer);
        
    } catch (error) {
        console.error('生成条形码出错:', error);
        res.status(500).json({ error: `生成条形码时出错: ${error.message}` });
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`服务器运行在环境: ${NODE_ENV}`);
    console.log(`服务端口: ${PORT}`);
    console.log(`访问地址: http://localhost:${PORT}`);
});

// 错误处理中间件
app.use((err, req, res, next) => {
    console.error('未捕获的错误:', err);
    res.status(500).json({ error: '服务器内部错误' });
});

// 404处理
app.use((req, res) => {
    res.status(404).json({ error: '请求的资源不存在' });
});

// 优雅关闭
process.on('SIGTERM', () => {
    console.log('收到终止信号，正在关闭服务器...');
    // 这里可以添加清理资源的代码
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('收到中断信号，正在关闭服务器...');
    // 这里可以添加清理资源的代码
    process.exit(0);
});