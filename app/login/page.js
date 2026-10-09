'use client';
import { useState } from 'react';
export default function Login() {
  const [register,setRegister]=useState(false),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  async function submit(event) {
    event.preventDefault();setBusy(true);setError('');
    const fields=Object.fromEntries(new FormData(event.currentTarget));
    try {
      const response=await fetch('/api/account',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...fields,action:register?'register':'login'})});
      const data=await response.json();if(!response.ok)throw new Error(data.error);
      window.location.assign('/');
    } catch(e){setError(e.message);} finally {setBusy(false);}
  }
  return <main style={{maxWidth:440,margin:'10vh auto',padding:28}}><h1>Inspector</h1>
    <h2>{register?'Create your workspace':'Sign in to your workspace'}</h2>
    <p>Your targets, scans, and risks are private to your workspace.</p>
    <form onSubmit={submit} style={{display:'grid',gap:16}}>
      {register&&<label>Workspace name<input name="workspaceName" required maxLength={100}/></label>}
      <label>Email<input name="email" type="email" autoComplete="email" required maxLength={254}/></label>
      <label>Password<input name="password" type="password" autoComplete={register?'new-password':'current-password'} required minLength={12} maxLength={128}/></label>
      <small>Use at least 12 characters.</small>
      {error&&<p role="alert">{error}</p>}
      <button type="submit" disabled={busy}>{busy?'Please wait…':register?'Create workspace':'Sign in'}</button>
    </form>
    <button onClick={()=>{setRegister(!register);setError('');}} style={{marginTop:20}}>{register?'Already have an account? Sign in':'Create a new workspace'}</button>
  </main>;
}
