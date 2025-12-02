document.addEventListener('DOMContentLoaded', () => {
    // 使用相对路径作为API基础URL
    const apiBaseUrl = '/';
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
            const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        text: barcodeText,
        width: barcodeWidth,    // 用户输入的宽度(mm)
        height: barcodeHeight,  // 用户输入的高度(mm)
        type: 'code128'
    })
});
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || '生成条码失败');
            }
            
            // 将响应转换为Blob
            const blob = await response.blob();
            
            // 直接下载条码图片
            const sanitizedText = barcodeText.replace(/[^a-z0-9]/gi, '_').substring(0, 20); // 清理文件名
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
    
    // 设置功能相关代码
    const settingsBtn = document.getElementById('settingsBtn');
    const settingsModal = document.getElementById('settingsModal');
    const closeBtn = document.querySelector('.close-btn');
    const closeSettingsBtn = document.querySelector('.close-settings');
    const settingsForm = document.getElementById('settingsForm');
    const settingsError = document.getElementById('settingsError');
    const settingsSuccess = document.getElementById('settingsSuccess');
    const singleBarcodeWidthMmInput = document.getElementById('singleBarcodeWidthMm');
    const spacingMmInput = document.getElementById('spacingMm');
    
    // 显示设置模态框
    settingsBtn.addEventListener('click', async () => {
        try {
            // 获取当前配置
            const response = await fetch(`${apiBaseUrl}get-barcode-config`);
            if (response.ok) {
                const config = await response.json();
                // 填充表单
                singleBarcodeWidthMmInput.value = config.singleBarcodeWidthMm || 50;
                spacingMmInput.value = config.spacingMm || 7.5;
            }
        } catch (error) {
            // 静默失败，使用默认值
        }
        
        // 重置消息
        settingsError.style.display = 'none';
        settingsSuccess.style.display = 'none';
        
        // 显示模态框
        settingsModal.style.display = 'flex';
    });
    
    // 关闭模态框函数
    const closeModal = () => {
        settingsModal.style.display = 'none';
        // 重置表单字段（手动重置，避免重置已删除的password字段）
        singleBarcodeWidthMmInput.value = 50;
        spacingMmInput.value = 7.5;
        settingsError.style.display = 'none';
        settingsSuccess.style.display = 'none';
    };
    
    // 关闭模态框事件
    closeBtn.addEventListener('click', closeModal);
    closeSettingsBtn.addEventListener('click', closeModal);
    
    // 点击模态框外部关闭
    window.addEventListener('click', (event) => {
        if (event.target === settingsModal) {
            closeModal();
        }
    });
    
    // 阻止模态框内点击事件冒泡
    settingsModal.querySelector('.modal-content').addEventListener('click', (event) => {
        event.stopPropagation();
    });
    
    // 表单提交处理
    settingsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const singleBarcodeWidthMm = parseFloat(singleBarcodeWidthMmInput.value);
        const spacingMm = parseFloat(spacingMmInput.value);
        
        // 客户端验证
        
        if (isNaN(singleBarcodeWidthMm) || singleBarcodeWidthMm <= 0) {
            showSettingsError('单个条码宽度必须是大于0的有效数字');
            return;
        }
        
        if (isNaN(spacingMm) || spacingMm < 0) {
            showSettingsError('条码间隙必须是大于等于0的有效数字');
            return;
        }
        
        try {
            const response = await fetch(`${apiBaseUrl}set-barcode-config`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    singleBarcodeWidthMm,
                    spacingMm
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showSettingsSuccess('设置已成功保存');
                // 3秒后关闭模态框
                setTimeout(() => {
                    closeModal();
                }, 3000);
            } else {
                showSettingsError(data.error || '保存设置失败');
            }
        } catch (error) {
            showSettingsError('保存设置时发生错误，请稍后重试');
        }
    });
    
    // 显示设置错误消息
    function showSettingsError(message) {
        settingsError.querySelector('p').textContent = message;
        settingsError.style.display = 'block';
        settingsSuccess.style.display = 'none';
    }
    
    // 显示设置成功消息
    function showSettingsSuccess(message) {
        settingsSuccess.querySelector('p').textContent = message;
        settingsSuccess.style.display = 'block';
        settingsError.style.display = 'none';
    }
});