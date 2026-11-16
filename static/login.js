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
