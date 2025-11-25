document.addEventListener('DOMContentLoaded', () => {
    // 配置API基础URL
const apiBaseUrl = '/'; // 相对路径
    
const verificationForm = document.getElementById('verification-form');
const messageElement = document.getElementById('message');
const countdownElement = document.getElementById('countdown');
let countdownInterval;
    
    // 表单提交事件处理
verificationForm.addEventListener('submit', async (e) => {
    e.preventDefault();
        
    const code = document.getElementById('verification-code').value.trim();
    
    // 客户端验证
    if (!code || code.length !== 4 || !/^\d+$/.test(code)) {
        showMessage('请输入4位数字验证码', 'error');
        return;
    }
        
    try {
        // 禁用按钮防止重复提交
        const submitBtn = verificationForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = '验证中...';
        
        hideMessage();
        
        // 调用验证API
       // 在表单提交事件中
const response = await fetch(`${apiBaseUrl}verify-code`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code }),
    credentials: 'include' // 重要：确保发送Cookie
});
            
        const data = await response.json();
        
        // 验证成功处理
        if (response.ok) {
            // 验证成功
            showMessage('验证成功，正在跳转到条码生成页面...', 'success');
            
            // 简化跳转逻辑，只使用一次跳转
            setTimeout(() => {
                // 使用 replace 避免历史记录问题
                window.location.replace('/');
            }, 1000); // 延长等待时间确保Cookie设置完成
        } else {
            // 验证失败
            if (data.error && data.error.includes('请求过于频繁')) {
                // 显示倒计时
                const match = data.error.match(/请(\d+)分钟后再试/);
                if (match && match[1]) {
                    const minutes = parseInt(match[1]);
                    startCountdown(minutes);
                }
            }
            showMessage(data.error || '验证失败，请重试', 'error');
        }
    } catch (error) {
        // 错误已记录在服务器端，这里只向用户显示友好提示
        showMessage('服务器错误，请稍后重试', 'error');
    } finally {
        // 恢复按钮状态
        const submitBtn = verificationForm.querySelector('button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.textContent = '验证';
    }
    });
    
// 显示消息
function showMessage(text, type = 'info') {
    messageElement.textContent = text;
    messageElement.className = `message ${type}`;
    messageElement.style.display = 'block';
}
    
// 隐藏消息
function hideMessage() {
    messageElement.style.display = 'none';
}
    
// 开始倒计时
function startCountdown(minutes) {
    let totalSeconds = minutes * 60;
    
    // 显示倒计时元素
    countdownElement.style.display = 'block';
    
    // 禁用表单
    const submitBtn = verificationForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    
    // 更新倒计时
    updateCountdownDisplay(totalSeconds);
    
    // 清除之前的倒计时
    if (countdownInterval) {
        clearInterval(countdownInterval);
    }
    
    // 设置新的倒计时
    countdownInterval = setInterval(() => {
        totalSeconds--;
        
        if (totalSeconds <= 0) {
            clearInterval(countdownInterval);
            countdownElement.style.display = 'none';
            submitBtn.disabled = false;
            showMessage('您现在可以再次尝试验证', 'info');
        } else {
            updateCountdownDisplay(totalSeconds);
        }
    }, 1000);
}
    
// 更新倒计时显示
function updateCountdownDisplay(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    countdownElement.innerHTML = `请等待 <span class="countdown">${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}</span> 后再试`;
}
    
// 页面卸载时清除定时器
window.addEventListener('beforeunload', () => {
    if (countdownInterval) {
        clearInterval(countdownInterval);
    }
});
});