import { AsyncLocalStorage } from 'node:async_hooks';
const scope=new AsyncLocalStorage();
export const inWorkspace=(context,fn)=>scope.run(context,fn);
export function workspaceContext() {
  const context=scope.getStore();
  if(!context?.workspaceId) throw new Error('Authenticated workspace context is required.');
  return context;
}
