import net from 'node:net';
// Deny special-use ranges; notifications only need ordinary globally routed addresses.
export function isPublicAddress(ip) {
  if(net.isIPv4(ip)) {
    const [a,b,c]=ip.split('.').map(Number);
    return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||
      (a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||b===88&&c===99))||
      (a===198&&(b===18||b===19||b===51&&c===100))||(a===203&&b===0&&c===113));
  }
  // Restrict IPv6 to global unicast; exclude documentation and transition mechanisms.
  if(net.isIPv6(ip)) {
    const expanded=new URL('http://['+ip+']/').hostname.slice(1,-1).toLowerCase();
    const first=parseInt(expanded.split(':')[0],16);
    return first>=0x2000&&first<=0x3fff&&!/^2001:(?:0:|db8:|[0-9a-f]{1,3}:)/.test(expanded)&&!expanded.startsWith('2002:')&&!expanded.startsWith('3fff:');
  }
  return false;
}
export function validateWebhookUrl(value) {
  const url=new URL(value);
  if(url.protocol!=='https:'||url.username||url.password||(url.port&&url.port!=='443')) throw new Error('Use a public HTTPS webhook on port 443 without embedded credentials.');
  const host=url.hostname.replace(/^\[|\]$/g,'');
  if(host==='localhost'||host.endsWith('.local')||host.endsWith('.internal')||(net.isIP(host)&&!isPublicAddress(host))) throw new Error('Webhook must use a public internet address.');
  return url;
}
