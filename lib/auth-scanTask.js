import {saveScan,latestStoredScan} from './backend/scanRepository';
import { workspaceContext } from './backend/context';
import { readState } from './store';
import { runAuthenticatedScan } from './authenticatedScan';
import { generateIntelligence } from './intelligence';

export async function runAuthenticatedTask(body,progress){
    const state = await readState({history:false});
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');
    const asset = project.assets.find((item) => item.id === body.assetId);
    if (!asset||asset.status!=='active') throw new Error('Active asset not found.');

      await progress(12, 'Preparing authorized test session');
      const sourceScan=await latestStoredScan('web',project.id,{assetId:asset.id,mode:'deep'})||await latestStoredScan('web',project.id,{assetId:asset.id});
      const previous=await latestStoredScan('auth',project.id,{assetId:asset.id,auth:{method:body.authType}});

      await progress(40, 'Running authenticated browser and API checks');
      const authScan = await runAuthenticatedScan({
        url:asset.url,
        sourceScan,
        previousScan:previous,
        auth:{type:body.authType,value:String(body.credential)}
      });
      authScan.projectId = project.id;
      authScan.assetId = asset.id;
      authScan.scanType = 'Authenticated Scan';
      authScan.status = authScan.status || 'completed';

      await progress(78, 'Generating evidence-based remediation');
      try {
        const intelligence = await generateIntelligence(authScan);
        authScan.intelligence = {
          mode:intelligence?.mode || 'rules',
          provider:intelligence?.provider || null,
          model:intelligence?.model || null,
          generatedAt:intelligence?.generatedAt || new Date().toISOString(),
          aiError:intelligence?.aiError || null
        };
        authScan.remediationPlan = intelligence;
        if (intelligence?.executiveSummary) authScan.executiveSummary = intelligence.executiveSummary;
      } catch (error) {
        authScan.intelligence = {mode:'rules',aiError:String(error?.message || error).slice(0,300)};
      }

      await progress(92, 'Saving authenticated scan results');
      authScan.id=workspaceContext().jobId||authScan.id;
  await saveScan('auth',authScan);
      return authScan;
    
}


