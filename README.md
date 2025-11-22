# 在线条形码生成器

这是一个基于Node.js和Express开发的在线条形码生成工具，支持自定义条码内容、宽度和高度。

## 功能特性

- 自定义条码内容输入
- 支持设置条码宽度（毫米）
- 支持设置条码高度（毫米）
- 实时预览生成的条码
- 下载条码图片（PNG格式）
- 响应式设计，支持移动端访问

## 技术栈

- **后端**：Node.js, Express
- **条形码生成**：bwip-js
- **前端**：HTML, CSS, JavaScript

## 安装与运行

### 环境要求

- Node.js (v14或更高版本)
- npm

### 安装步骤

1. 克隆或下载本项目

2. 安装依赖
   ```bash
   npm install
   ```

3. 启动开发服务器
   ```bash
   npm run dev
   ```

4. 启动生产服务器
   ```bash
   npm start
   ```

5. 访问应用
   打开浏览器，访问 http://localhost:3001

## API 文档

### 生成条形码

- **URL**: `/generate-barcode`
- **方法**: `POST`
- **请求体**:
  ```json
  {
    "text": "条码内容",
    "width": 100,  // 宽度（毫米）
    "height": 50   // 高度（毫米）
  }
  ```
- **响应**: 返回PNG格式的条形码图片

## 部署到腾讯云

### 准备工作

1. 确保项目可以正常运行
2. 在腾讯云控制台创建云服务器实例
3. 安装Node.js和npm

### 部署步骤

1. 将项目文件上传到云服务器

2. 安装依赖
   ```bash
   npm install --production
   ```

3. 使用PM2管理进程（推荐）
   ```bash
   npm install -g pm2
   pm2 start server.js --name "barcode-generator"
   pm2 startup
   pm2 save
   ```

4. 配置域名和反向代理
   - 安装Nginx
   - 配置Nginx反向代理到Node.js服务

## 许可证

MIT