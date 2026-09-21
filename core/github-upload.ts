/** Declared target only. Never execute git, expand aliases, read .git/config or follow redirects. */
export function githubTarget(command:string):'github'|'other'|'unknown' {
 if(/[\r\n;|&`$<>]/.test(command)||/\s(?:-c|-C|--git-dir|--work-tree|-L|--location(?:-trusted)?|--proxy|--connect-to|--resolve|-H|--header)\b/.test(command))return 'unknown';
 const urls=command.match(/(?:https?:\/\/|ssh:\/\/)[^\s'"<>]+|git@github\.com:[^\s'"<>]+/gi)??[];
 if(!urls.length)return 'unknown';
 let github=false;
 for(const raw of urls){
  if(/^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(raw)){github=true;continue;}
  try{const u=new URL(raw);if(!['https:','ssh:'].includes(u.protocol)||u.password||u.port&&u.port!=='443'&&!(u.protocol==='ssh:'&&u.port==='22')||u.username&&!(u.protocol==='ssh:'&&u.username==='git'))return 'unknown';
   if(!['github.com','api.github.com','uploads.github.com'].includes(u.hostname.toLowerCase()))return 'other';
   github=true;
  }catch{return 'unknown';}
 }
 return github?'github':'unknown';
}
