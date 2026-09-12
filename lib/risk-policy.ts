export type Risk = 'HIGH'|'MEDIUM'|'LOW';
const identity=new Set(['openid','email','profile','https://www.googleapis.com/auth/userinfo.email','https://www.googleapis.com/auth/userinfo.profile']);
export function riskFloor(scopes:string[]):Risk {
 if(scopes.some(s=>/admin\.|mail\.google\.com|gmail\.(modify|compose|send)|\/auth\/drive$|\/auth\/cloud-platform$/.test(s))) return 'HIGH';
 if(scopes.length===0 || scopes.some(s=>!identity.has(s))) return 'MEDIUM'; return 'LOW';
}
export function maxRisk(a:Risk,b:Risk):Risk { const levels:Risk[]=['LOW','MEDIUM','HIGH']; return levels[Math.max(levels.indexOf(a),levels.indexOf(b))]; }
