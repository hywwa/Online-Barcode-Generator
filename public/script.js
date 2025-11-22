document.addEventListener('DOMContentLoaded', () => {
    // 配置API基础URL - 自适应不同环境
    const getApiBaseUrl = () => {
        const hostname = window.location.hostname;
        const port = window.location.port;
        
        // 生产环境直接使用相对路径
        if (hostname === '106.53.219.143') {
            return '/'; // 通过Nginx反向代理
        }
        
        // 本地开发环境 - 使用80端口访问时通过代理，否则直接指向3001
        if (port === '80' || port === '') {
            return '/';
        }
        
        // 其他情况使用相对路径
        return '/';
    };
    
    const apiBaseUrl = getApiBaseUrl();
    console.log(`API基础URL: ${apiBaseUrl}`);
    const barcodeForm = document.getElementById('barcodeForm');
    const errorContainer = document.getElementById('errorContainer');
    const errorText = document.getElementById('errorText');
    
    const barcodeTextInput = document.getElementById('barcodeText');
    const barcodeWidthInput = document.getElementById('barcodeWidth');
    const barcodeHeightInput = document.getElementById('barcodeHeight');
    
    let isGenerating = false; // 防止重复提交
    
    // 添加实时输入验证
    barcodeTextInput.addEventListener('input', () => {
        const value = barcodeTextInput.value.trim();
        if (value.length > 100) {
            showError('条码内容不能超过100个字符');
        } else {
            hideError();
        }
    });
    
    barcodeWidthInput.addEventListener('blur', () => {
        const value = parseFloat(barcodeWidthInput.value);
        if (isNaN(value) || value <= 0) {
            showError('宽度必须是大于0的数字');
        } 
        else {
            hideError();
        }
    });
    
    barcodeHeightInput.addEventListener('blur', () => {
        const value = parseFloat(barcodeHeightInput.value);
        if (isNaN(value) || value <= 0) {
            showError('高度必须是大于0的数字');
        } else {
            hideError();
        }
    });
    
    // 表单提交事件处理
    barcodeForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // 防止重复提交
        if (isGenerating) return;
        
        // 获取表单数据
        const barcodeText = barcodeTextInput.value.trim();
        const barcodeWidth = parseFloat(barcodeWidthInput.value);
        const barcodeHeight = parseFloat(barcodeHeightInput.value);
        
        // 客户端验证
        if (!barcodeText) {
            showError('请输入条码内容');
            barcodeTextInput.focus();
            return;
        }
        
        if (barcodeText.length > 100) {
            showError('条码内容不能超过100个字符');
            barcodeTextInput.focus();
            return;
        }
        
        if (isNaN(barcodeWidth) || barcodeWidth <= 0) {
            showError('请输入有效的宽度值（必须大于0）');
            barcodeWidthInput.focus();
            return;
        }
        
        
        if (isNaN(barcodeHeight) || barcodeHeight <= 0) {
            showError('请输入有效的高度值（必须大于0）');
            barcodeHeightInput.focus();
            return;
        }
        
        try {
            hideError();
            isGenerating = true;
            
            // 更改按钮文本为加载状态
            const submitBtn = barcodeForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.textContent;
            submitBtn.textContent = '正在生成...';
            submitBtn.disabled = true;
            
            
            // 调用API生成条码
            const apiUrl = `${apiBaseUrl}generate-barcode`;
            console.log(`调用API: ${apiUrl}`);
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                text: barcodeText,
                width: barcodeWidth,
                height: barcodeHeight,
                type: 'code128', // 可以扩展为用户可选择的类型
                // 根据总宽度和每个条形码宽度50mm自动计算重复数量
                totalWidth: barcodeWidth,
                singleBarcodeWidth: 50 // 每个条形码的固定宽度(mm)
            })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || '生成条码失败');
            }
            
            // 将响应转换为Blob
            const blob = await response.blob();
            
            // 直接处理新的条码下载，不需要清理旧的URL对象
            
            // 直接下载条码图片
            const sanitizedText = barcodeText.replace(/[^a-z0-9]/gi, '_').substring(0, 20); // 清理文件名
            // 计算条码数量（根据总宽度和单个条码宽度）
            const count = Math.max(1, Math.floor(barcodeWidth / 50)); // 假设每个条码50mm宽
            const filename = `${sanitizedText}(${barcodeWidth}x${barcodeHeight}).png`;
            
            // 创建下载链接并触发下载
            const downloadUrl = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = filename;
            document.body.appendChild(link);
            
            // 触发下载
            link.click();
            
            // 延迟清理
            setTimeout(() => {
                document.body.removeChild(link);
                URL.revokeObjectURL(downloadUrl);
            }, 100);
            
        } catch (error) {
            console.error('生成条码时出错:', error);
            showError(error.message || '生成条码时发生错误，请稍后重试');
        } finally {
            // 恢复按钮状态
            isGenerating = false;
            const submitBtn = barcodeForm.querySelector('button[type="submit"]');
            submitBtn.textContent = '生成条码';
            submitBtn.disabled = false;
        }
    });
    
    // 显示错误信息
    function showError(message) {
        errorText.textContent = message;
        errorContainer.style.display = 'block';
        
        // 3秒后自动隐藏错误信息（如果不是表单提交时的错误）
        setTimeout(() => {
            hideError();
        }, 3000);
    }
    
    // 隐藏错误信息
    function hideError() {
        errorContainer.style.display = 'none';
    }
    
    // 为输入框添加焦点样式
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.boxShadow = '0 0 0 2px rgba(52, 152, 219, 0.1)';
        });
        
        input.addEventListener('blur', () => {
            input.parentElement.style.boxShadow = 'none';
        });
    });
});