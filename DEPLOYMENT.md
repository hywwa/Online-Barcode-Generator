# 条形码生成器项目部署指南

## 部署步骤

1. **构建项目**：
   ```bash
   # 在本地项目目录中运行
   npm run build
   ```

2. **上传dist目录到服务器**：
   ```bash
   #上传
  /www/wwwroot/Barcode/dist/
   ```

3. **安装依赖**：
   ```bash
   cd /www/wwwroot/Barcode/dist
   npm install --production
   ```

4. **启动服务**：
   ```bash
   # 查看所有运行的服务
   pm2 list
   
   # 重启服务（改代码后生效）
   pm2 restart barcode
   ```

## 注意事项

- 确保服务器上已安装Node.js 14.x或兼容版本，以避免GLIBC版本兼容性问题
- 如果使用PM2，请确保已正确配置ecosystem.config.js文件
- 如遇到端口占用问题，可修改server.js中的端口配置
- 确保服务器防火墙已开放相应端口（默认为3001）