// ============================================================
// 文件名称：login.js
// 生成日期：2026-11-15
// 修改日期：2026-11-20
// 版本信息：v0.261115
// 作    者：JUN
// 备    注：本程序由AI辅助完成。
//           文件功能：实现 login 模块相关功能。
//           文件用途：供WAF的 yuhan/static/login.js 模块使用。
//           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
// ============================================================
'use strict';
const form=document.getElementById('login-form'),message=document.getElementById('login-message');
if(new URLSearchParams(location.search).get('reason')==='logout')message.textContent='已安全退出，请重新登录。';
if(new URLSearchParams(location.search).get('reason')==='password')message.textContent='密码已更新，请使用新密码登录。';
form.addEventListener('submit',async event=>{
  event.preventDefault();const button=document.getElementById('login-submit');button.disabled=true;message.textContent='';
  try{
    const response=await fetch('/api/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value.trim(),password:document.getElementById('password').value})});
    const result=await response.json();
    if(!response.ok)throw Error(typeof result.detail==='string'?result.detail:'登录失败，请检查输入。');
    document.getElementById('password').value='';location.replace('/');
  }catch(error){message.textContent=error.message;}finally{button.disabled=false;}
});
