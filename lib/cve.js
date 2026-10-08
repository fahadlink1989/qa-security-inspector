const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const CPE_BUILDERS = {
  'PHP': (version) => `cpe:2.3:a:php:php:${version}:*:*:*:*:*:*:*`,
  'WordPress': (version) => `cpe:2.3:a:wordpress:wordpress:${version}:*:*:*:*:*:*:*`,
  'Apache HTTP Server': (version) => `cpe:2.3:a:apache:http_server:${version}:*:*:*:*:*:*:*`,
  'nginx': (version) => `cpe:2.3:a:nginx:nginx:${version}:*:*:*:*:*:*:*`
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function englishDescription(cve) {
  return (cve.descriptions || []).find((item) => item.lang === 'en')?.value || '';
}

function cvssData(cve) {
  const sets = [
    ...(cve.metrics?.cvssMetricV40 || []),
    ...(cve.metrics?.cvssMetricV31 || []),
    ...(cve.metrics?.cvssMetricV30 || []),
    ...(cve.metrics?.cvssMetricV2 || [])
  ];

  for (const metric of sets) {
    const data = metric.cvssData || {};
    if (typeof data.baseScore === 'number') {
      return {
        version: data.version || null,
        score: data.baseScore,
        severity: data.baseSeverity || metric.baseSeverity || null,
        vector: data.vectorString || null
      };
    }
  }

  return { version:null, score:null, severity:null, vector:null };
}

function cwes(cve) {
  return [...new Set((cve.weaknesses || []).flatMap((entry) =>
    (entry.description || []).filter((item) => item.lang === 'en').map((item) => item.value)
  ))].filter(Boolean).slice(0,8);
}

function references(cve) {
  return (cve.references || []).slice(0,8).map((item) => ({
    url:item.url,
    source:item.source || null,
    tags:item.tags || []
  }));
}


function versionParts(value) {
  return String(value || '')
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map((item)=>Number(item));
}

function compareVersions(a,b) {
  const left=versionParts(a);
  const right=versionParts(b);
  const length=Math.max(left.length,right.length);
  for(let i=0;i<length;i+=1){
    const av=left[i]||0;
    const bv=right[i]||0;
    if(av>bv) return 1;
    if(av<bv) return -1;
  }
  return 0;
}

function criteriaVersion(criteria) {
  const parts=String(criteria||'').split(':');
  return parts.length>=6 ? parts[5] : '*';
}

function explicitMatchApplies(match,targetVersion) {
  if(!match || match.vulnerable !== true) return false;
  const exact=criteriaVersion(match.criteria);
  if(exact && exact !== '*' && exact !== '-') {
    return compareVersions(targetVersion,exact)===0;
  }

  const hasBounds=Boolean(
    match.versionStartIncluding ||
    match.versionStartExcluding ||
    match.versionEndIncluding ||
    match.versionEndExcluding
  );
  if(!hasBounds) return false;

  if(match.versionStartIncluding && compareVersions(targetVersion,match.versionStartIncluding)<0) return false;
  if(match.versionStartExcluding && compareVersions(targetVersion,match.versionStartExcluding)<=0) return false;
  if(match.versionEndIncluding && compareVersions(targetVersion,match.versionEndIncluding)>0) return false;
  if(match.versionEndExcluding && compareVersions(targetVersion,match.versionEndExcluding)>=0) return false;
  return true;
}

function configurationApplies(configurations,targetVersion) {
  const matches=[];
  function walk(node){
    for(const item of node?.cpeMatch||[]) matches.push(item);
    for(const child of node?.nodes||[]) walk(child);
  }
  for(const configuration of configurations||[]) {
    for(const node of configuration.nodes||[]) walk(node);
  }
  return matches.some((match)=>explicitMatchApplies(match,targetVersion));
}

function severityFromScore(score) {
  if (score == null) return 'Unknown';
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  if (score > 0) return 'Low';
  return 'None';
}

export function cpeForTechnology(technology) {
  const name = technology?.name;
  const version = technology?.version;
  if (!name || !version || !CPE_BUILDERS[name]) return null;
  return CPE_BUILDERS[name](String(version).trim());
}

async function fetchNvd(cpe) {
  const headers = {
    accept:'application/json',
    'user-agent':'InspectorQA/2.2 (+authorized vulnerability enrichment)'
  };
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;

  const url = NVD_BASE + '?cpeName=' + encodeURIComponent(cpe) + '&resultsPerPage=30';
  const response = await fetch(url, {
    headers,
    cache:'no-store',
    signal:AbortSignal.timeout(18000)
  });

  if (!response.ok) throw new Error('NVD returned HTTP ' + response.status);
  return response.json();
}

export async function enrichTechnologiesWithCves(technologies, options={}) {
  const candidates = [];
  const seen = new Set();

  for (const technology of technologies || []) {
    const cpe = cpeForTechnology(technology);
    if (!cpe || seen.has(cpe)) continue;
    seen.add(cpe);
    candidates.push({technology,cpe});
  }

  const limit = Math.min(Number(options.maxTechnologies || 3), 3);
  const output = [];
  const errors = [];

  for (let index=0; index<candidates.slice(0,limit).length; index+=1) {
    const candidate = candidates[index];

    try {
      const data = await fetchNvd(candidate.cpe);
      const vulnerabilities = [];

      for (const wrapper of data.vulnerabilities || []) {
        const cve = wrapper.cve;
        if (!cve?.id) continue;
        if (!configurationApplies(cve.configurations,candidate.technology.version)) continue;
        const cvss = cvssData(cve);
        vulnerabilities.push({
          id:cve.id,
          technology:candidate.technology.name,
          version:candidate.technology.version,
          cpe:candidate.cpe,
          published:cve.published || null,
          lastModified:cve.lastModified || null,
          description:englishDescription(cve).slice(0,1800),
          cvss:{
            ...cvss,
            severity:cvss.severity || severityFromScore(cvss.score)
          },
          cwes:cwes(cve),
          references:references(cve),
          source:'NVD'
        });
      }

      vulnerabilities.sort((a,b)=>(b.cvss.score || 0)-(a.cvss.score || 0));
      output.push({
        technology:candidate.technology,
        cpe:candidate.cpe,
        candidateResults:Number(data.totalResults || 0),
        validatedResults:vulnerabilities.length,
        matchingPolicy:'explicit version/range applicability only',
        vulnerabilities:vulnerabilities.slice(0,30)
      });
    } catch (error) {
      errors.push({
        technology:candidate.technology,
        cpe:candidate.cpe,
        error:String(error?.message || error).slice(0,300)
      });
    }

    if (!process.env.NVD_API_KEY && index < Math.min(candidates.length,limit)-1) {
      await sleep(6500);
    }
  }

  return {
    queried:candidates.slice(0,limit).length,
    skippedMatches:Math.max(0,candidates.length-limit),
    products:output,
    errors,
    vulnerabilities:output.flatMap((item)=>item.vulnerabilities)
  };
}
