import { workspaceContext } from './backend/context';
import { carryRiskLifecycle } from './riskModel.mjs';
import { mutateState, readState } from './store';
import { runAuthenticatedScan } from './authenticatedScan';
import { generateIntelligence } from './intelligence';

export async function runAuthenticatedTask(body,progress){
    const state = await readState();
    const project = state.projects.find((item) => item.id === body.projectId);
    if (!project) throw new Error('Project not found.');
    const asset = project.assets.find((item) => item.id === body.assetId);
    if (!asset||asset.status!=='active') throw new Error('Active asset not found.');

      await progress(12, 'Preparing authorized test session');
      const sourceScan = [...state.scans]
        .filter((item) => item.projectId === project.id && item.assetId === asset.id &&
          ['completed','completed_with_gaps','partial'].includes(item.status))
        .sort((a,b) => (a.mode === 'deep' ? -1 : 0) - (b.mode === 'deep' ? -1 : 0) ||
          String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;
      const previous = [...(project.authScans || [])]
        .filter((item) => item.assetId === asset.id && item.auth?.method === body.authType)
        .sort((a,b) => String(b.completedAt || '').localeCompare(String(a.completedAt || '')))[0] || null;

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
  await mutateState((next) => {
        const target = next.projects.find((item) => item.id === project.id);
        if (!target) throw new Error('Project not found.');
        carryRiskLifecycle(authScan,(target.authScans||[]).find(item=>item.assetId===authScan.assetId&&item.auth?.method===authScan.auth?.method));
        target.authScans = [authScan, ...(target.authScans || []).filter(item=>item.id!==authScan.id)].slice(0, 10);
        return next;
      });
      return authScan;
    
}
