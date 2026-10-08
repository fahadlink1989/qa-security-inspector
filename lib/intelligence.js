const GATEWAY_URL = 'https://ai-gateway.vercel.sh/v1/chat/completions';
const MODEL = 'alibaba/qwen-3-14b';

function compactScan(scan) {
  const rank = { Critical:5, High:4, Medium:3, Low:2, Informational:1 };
  const top = [...(scan.findings || [])]
    .sort((a,b)=>(rank[b.severity] || 0) - (rank[a.severity] || 0))
    .slice(0,10)
    .map((f)=>({severity:f.severity,title:f.title,category:f.category,engine:f.engine,summary:f.summary}));
  return {
    score: scan.score,
    summary: scan.summary,
    newFindings: (scan.findings || []).filter((f)=>f.lifecycle==='new').length,
    resolved: scan.resolvedFindings?.length || 0,
    pagesCrawled: scan.metrics?.pagesCrawled || 0,
    apiEndpoints: scan.metrics?.apiEndpoints || 0,
    technologies: scan.evidence?.inventory?.technologies || [],
    topFindings: top
  };
}

export async function generateIntelligence(scan) {
  const token = process.env.AI_GATEWAY_API_KEY || process.env.VERCEL_OIDC_TOKEN;
  if (!token) return null;

  const response = await fetch(GATEWAY_URL, {
    method: 'POST',
    headers: {
      authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: MODEL,
      temperature: 0.2,
      max_tokens: 500,
      messages: [
        {
          role: 'system',
          content: 'You are a web security and quality assurance analyst. Use only the supplied scan evidence. Do not invent vulnerabilities. Produce a concise executive summary followed by exactly three prioritized remediation actions. Make uncertainty explicit.'
        },
        {
          role: 'user',
          content: JSON.stringify(compactScan(scan))
        }
      ]
    }),
    signal: AbortSignal.timeout(15000)
  });

  if (!response.ok) throw new Error('AI Gateway returned ' + response.status);
  const data = await response.json();
  const text = data?.choices?.[0]?.message?.content?.trim();
  if (!text) return null;
  return {
    mode: 'ai',
    model: MODEL,
    generatedAt: new Date().toISOString(),
    summary: text
  };
}
