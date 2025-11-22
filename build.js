const fs = require('fs');
const path = require('path');

// 定义dist目录
const distDir = './dist';

// 确保目录存在的函数
function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`创建目录: ${dir}`);
    }
}

// 创建必要的目录结构
ensureDir(distDir);
ensureDir(path.join(distDir, 'public'));
ensureDir(path.join(distDir, 'public', 'assets'));

// 需要复制的文件列表
const filesToCopy = [
    { from: 'server.js', to: 'server.js' },
    { from: 'package.json', to: 'package.json' },
    { from: 'package-lock.json', to: 'package-lock.json' },
    { from: 'ecosystem.config.js', to: 'ecosystem.config.js' },
    { from: 'public/index.html', to: 'public/index.html' },
    { from: 'public/script.js', to: 'public/script.js' },
    { from: 'public/styles.css', to: 'public/styles.css' }
];

// 复制文件
filesToCopy.forEach(({ from, to }) => {
    try {
        const source = path.join(__dirname, from);
        const target = path.join(distDir, to);
        
        if (fs.existsSync(source)) {
            fs.copyFileSync(source, target);
            console.log(`复制文件: ${from} -> ${to}`);
            
            // 特殊处理package.json，修改scripts以解决Node.js PATH问题
            if (to === 'package.json') {
                try {
                    const packageJsonPath = target;
                    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
                    
                    // 修改start脚本，添加使用npx node的替代方案（更可靠的环境变量处理）
                    // 同时保留原始脚本作为注释
                    packageJson.scripts = {
                        ...packageJson.scripts,
                        "start": "npx node server.js",
                        "start:original": "node server.js"
                    };
                    
                    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
                    console.log(`已修改package.json中的scripts以解决Node.js PATH问题`);
                } catch (err) {
                    console.error(`修改package.json时出错:`, err.message);
                }
            }
        } else {
            console.warn(`跳过文件: ${from} (不存在)`);
        }
    } catch (error) {
        console.error(`复制文件出错 ${from} -> ${to}:`, error.message);
    }
});

// 复制assets目录中的图片文件
try {
    const assetsDir = path.join(__dirname, 'public', 'assets');
    if (fs.existsSync(assetsDir)) {
        fs.readdirSync(assetsDir).forEach(file => {
            if (file.endsWith('.png') || file.endsWith('.jpg') || file.endsWith('.jpeg') || file.endsWith('.gif')) {
                const source = path.join(assetsDir, file);
                const target = path.join(distDir, 'public', 'assets', file);
                if (fs.existsSync(source)) {
                    fs.copyFileSync(source, target);
                    console.log(`复制资源文件: public/assets/${file}`);
                }
            }
        });
    }
} catch (e) {
    console.warn('未找到assets目录或复制资源时出错:', e.message);
}

console.log('构建完成: dist目录已生成');